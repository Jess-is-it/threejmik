import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple

from app.db import get_db, utcnow
from app.services.config import settings
from app.services.mikrotik import MikroTikClient, normalize_export, sha256_text
from app.services.telegram import get_default_recipients, send_message


def parse_recipients(raw: str) -> list[str]:
    return [rid.strip() for rid in raw.split(",") if rid.strip()]


def safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value).strip("_")


def ensure_storage_dirs(router_name: str) -> tuple[Path, Path, Path]:
    router_dir = settings.storage_path / safe_name(router_name)
    backups_dir = router_dir / "backups"
    rsc_dir = router_dir / "rsc"
    backups_dir.mkdir(parents=True, exist_ok=True)
    rsc_dir.mkdir(parents=True, exist_ok=True)
    return router_dir, backups_dir, rsc_dir


def delete_old_local_files(folder: Path, retention_days: int) -> None:
    cutoff = datetime.utcnow().timestamp() - retention_days * 86400
    for entry in folder.iterdir():
        if not entry.is_file():
            continue
        if not entry.name.startswith("rv_"):
            continue
        if entry.stat().st_mtime <= cutoff:
            entry.unlink(missing_ok=True)


def is_baseline_due(router: Dict, now: datetime) -> bool:
    if not router.get("daily_baseline_time"):
        return False
    try:
        baseline_time = datetime.strptime(router["daily_baseline_time"], "%H:%M").time()
    except ValueError:
        return False
    last_baseline = router.get("last_baseline_at")
    last_baseline_date = None
    if last_baseline:
        try:
            last_baseline_date = datetime.fromisoformat(last_baseline).date()
        except ValueError:
            last_baseline_date = None
    if last_baseline_date == now.date():
        return False
    return now.time() >= baseline_time


def is_interval_due(router: Dict, now: datetime) -> bool:
    last_check = router.get("last_check_at")
    if not last_check:
        return True
    try:
        last_dt = datetime.fromisoformat(last_check)
    except ValueError:
        return True
    interval = timedelta(hours=router.get("backup_check_interval_hours") or 6)
    return now - last_dt >= interval


def should_force_backup(router: Dict, now: datetime) -> bool:
    last_success = router.get("last_success_at")
    if not last_success:
        return True
    try:
        last_dt = datetime.fromisoformat(last_success)
    except ValueError:
        return True
    days = router.get("force_backup_every_days") or 7
    return now - last_dt >= timedelta(days=days)


def detect_change(logs: list[dict], new_hash: str, old_hash: str | None) -> Tuple[bool, str]:
    changed = new_hash != (old_hash or "")
    summary = "Hash changed" if changed else "Hash unchanged"
    keyword_hit = False
    for entry in logs:
        message = (entry.get("message") or "").lower()
        topics = (entry.get("topics") or "").lower()
        if any(keyword in message or keyword in topics for keyword in settings.log_keywords):
            keyword_hit = True
            break
    if keyword_hit:
        changed = True
        summary = "Log keywords indicate change"
    return changed, summary


def run_router_check(router: Dict, baseline_due: bool) -> None:
    client = MikroTikClient(
        host=router["ip"],
        port=router["api_port"],
        timeout=router.get("api_timeout_seconds") or 5,
        username=router["username"],
        password=router["encrypted_password"],
        ftp_port=router.get("ftp_port") or 21,
    )
    now = datetime.utcnow()
    logs = client.fetch_logs(router.get("last_log_check_at"))
    export_text = client.export_config()
    normalized = normalize_export(export_text)
    new_hash = sha256_text(normalized)

    changed, summary = detect_change(logs, new_hash, router.get("last_hash"))
    forced = baseline_due and should_force_backup(router, now)
    needs_backup = changed or forced

    backup_link = ""
    rsc_link = ""
    if needs_backup:
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        router_slug = safe_name(router["name"])
        base_name = f"rv_{router_slug}_{stamp}"
        backup_name = f"{base_name}.backup"
        rsc_name = f"{base_name}.rsc"

        backup_bytes = client.create_backup(base_name)
        rsc_bytes = client.create_rsc_file(base_name)
        router_dir, backups_dir, rsc_dir = ensure_storage_dirs(router["name"])
        backup_path = backups_dir / backup_name
        rsc_path = rsc_dir / rsc_name
        backup_path.write_bytes(backup_bytes)
        rsc_path.write_bytes(rsc_bytes)

        retention_days = router.get("retention_days") or 30
        delete_old_local_files(backups_dir, retention_days)
        delete_old_local_files(rsc_dir, retention_days)

        base_url = f"/storage/{router_slug}"
        backup_link = f"{base_url}/backups/{backup_name}"
        rsc_link = f"{base_url}/rsc/{rsc_name}"

    with get_db(settings.db_path) as conn:
        conn.execute(
            """
            UPDATE routers
            SET last_log_check_at = ?,
                last_hash = ?,
                last_backup_at = ?,
                last_success_at = ?,
                last_error = ?,
                last_config_change_at = ?,
                last_backup_links = ?,
                last_check_at = ?,
                last_baseline_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                utcnow(),
                new_hash,
                utcnow() if needs_backup else router.get("last_backup_at"),
                utcnow() if needs_backup else router.get("last_success_at"),
                None,
                utcnow() if changed else router.get("last_config_change_at"),
                json.dumps({"backup": backup_link, "rsc": rsc_link}) if needs_backup else router.get("last_backup_links"),
                utcnow(),
                utcnow() if baseline_due else router.get("last_baseline_at"),
                utcnow(),
                router["id"],
            ),
        )
        backup_id = None
        if needs_backup:
            cursor = conn.execute(
                """
                INSERT INTO backups
                (router_id, created_at, rsc_hash, rsc_link, backup_link, change_summary, logs, was_forced, was_changed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    router["id"],
                    utcnow(),
                    new_hash,
                    rsc_link,
                    backup_link,
                    summary,
                    json.dumps(logs),
                    1 if forced else 0,
                    1 if changed else 0,
                ),
            )
            backup_id = cursor.lastrowid
        for entry in logs:
            conn.execute(
                """
                INSERT INTO router_logs
                (router_id, logged_at, topics, message, backup_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    router["id"],
                    entry.get("logged_at") or "",
                    entry.get("topics") or "",
                    entry.get("message") or "",
                    backup_id,
                    utcnow(),
                ),
            )

    if needs_backup:
        recipients = get_default_recipients()
        message = (
            f"RouterVault backup for {router['name']}\n"
            f"Changed: {changed} Forced: {forced}\n"
            f"Backup: {backup_link}\nRSC: {rsc_link}"
        )
        if recipients:
            send_message(recipients, message)


def run_scheduled_checks() -> None:
    now = datetime.utcnow()
    with get_db(settings.db_path) as conn:
        routers = conn.execute(
            """
            SELECT *
            FROM routers
            WHERE enabled = 1
            """
        ).fetchall()
        conn.execute(
            "UPDATE settings SET last_scheduler_run = ? WHERE id = 1",
            (utcnow(),),
        )
    for router in routers:
        router_dict = dict(router)
        baseline_due = is_baseline_due(router_dict, now)
        interval_due = is_interval_due(router_dict, now)
        if baseline_due or interval_due:
            try:
                run_router_check(router_dict, baseline_due)
            except Exception as exc:
                with get_db(settings.db_path) as conn:
                    conn.execute(
                        """
                        UPDATE routers
                        SET last_error = ?, last_check_at = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (str(exc), utcnow(), utcnow(), router_dict["id"]),
                    )
