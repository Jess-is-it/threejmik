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


def get_global_force_days(default: int = 3) -> int:
    try:
        with get_db(settings.db_path) as conn:
            row = conn.execute("SELECT stale_backup_days FROM settings WHERE id = 1").fetchone()
        value = int(row["stale_backup_days"]) if row and row["stale_backup_days"] is not None else default
        return max(1, value)
    except Exception:
        return default


def should_force_backup(router: Dict, now: datetime, global_force_days: int) -> bool:
    last_success = router.get("last_success_at")
    if not last_success:
        return True
    try:
        last_dt = datetime.fromisoformat(last_success)
    except ValueError:
        return True
    router_days = int(router.get("force_backup_every_days") or global_force_days or 7)
    days = max(1, min(int(global_force_days or router_days), router_days))
    return now - last_dt >= timedelta(days=days)


def detect_change(logs: list[dict], new_hash: str, old_hash: str | None) -> Tuple[bool, str]:
    hash_changed = new_hash != (old_hash or "")
    logs_indicate_change = bool(logs)
    if hash_changed:
        return True, "Hash changed"
    if logs_indicate_change:
        return True, "Config-change logs detected"
    return False, "No changes detected"


def run_router_check(
    router: Dict,
    baseline_due: bool,
    force: bool = False,
    global_force_days: int | None = None,
    trigger: str = "auto",
) -> None:
    client = MikroTikClient(
        host=router["ip"],
        port=router["api_port"],
        timeout=router.get("api_timeout_seconds") or 5,
        username=router["username"],
        password=router["encrypted_password"],
        ftp_port=router.get("ftp_port") or 21,
    )
    now = datetime.utcnow()
    detection_logs = client.fetch_logs(router.get("last_log_check_at"))
    log_cursor = client.get_router_clock_iso()
    try:
        cursor_dt = datetime.fromisoformat(log_cursor) - timedelta(seconds=1)
        log_cursor = cursor_dt.replace(microsecond=0).isoformat(sep=" ")
    except ValueError:
        pass
    export_text = client.export_config()
    normalized = normalize_export(export_text)
    new_hash = sha256_text(normalized)

    changed, summary = detect_change(detection_logs, new_hash, router.get("last_hash"))
    if global_force_days is None:
        global_force_days = get_global_force_days()
    forced = bool(force) or (baseline_due and should_force_backup(router, now, global_force_days))
    needs_backup = changed or forced

    backup_link = ""
    rsc_link = ""
    backup_logs: list[dict] = []
    backup_log_cursor: str | None = router.get("last_backup_log_at")
    if needs_backup:
        backup_logs = client.fetch_logs(backup_log_cursor)

        # If this time window contains too much log noise, keep the backup's
        # logs focused on the most recent "detection" window (e.g. last 2 hours).
        max_backup_logs = 200
        noisy_threshold = 400
        if len(backup_logs) > noisy_threshold:
            backup_logs = detection_logs
            backup_log_cursor = log_cursor

        if len(backup_logs) > max_backup_logs:
            backup_logs = backup_logs[-max_backup_logs:]

        latest_log_dt: datetime | None = None
        for entry in backup_logs:
            logged_at = entry.get("logged_at") or ""
            try:
                dt = datetime.fromisoformat(logged_at)
            except ValueError:
                continue
            if latest_log_dt is None or dt > latest_log_dt:
                latest_log_dt = dt
        if latest_log_dt is not None:
            backup_log_cursor = (latest_log_dt + timedelta(seconds=1)).replace(microsecond=0).isoformat(sep=" ")
        else:
            backup_log_cursor = log_cursor

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

        base_url = f"/download/{router_slug}"
        backup_link = f"{base_url}/backups/{backup_name}"
        rsc_link = f"{base_url}/rsc/{rsc_name}"

    with get_db(settings.db_path) as conn:
        conn.execute(
            """
            UPDATE routers
            SET last_log_check_at = ?,
                last_backup_log_at = ?,
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
                log_cursor,
                backup_log_cursor if needs_backup else router.get("last_backup_log_at"),
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
                (router_id, created_at, rsc_hash, rsc_link, backup_link, change_summary, logs, trigger, was_forced, was_changed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    router["id"],
                    utcnow(),
                    new_hash,
                    rsc_link,
                    backup_link,
                    summary,
                    json.dumps(backup_logs),
                    trigger,
                    1 if forced else 0,
                    1 if changed else 0,
                ),
            )
            backup_id = cursor.lastrowid
        logs_to_store = backup_logs if needs_backup else detection_logs
        for entry in logs_to_store:
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
    global_force_days = get_global_force_days()
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
                run_router_check(router_dict, baseline_due, force=False, global_force_days=global_force_days)
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
