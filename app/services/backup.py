import json
from datetime import datetime, timedelta
from typing import Dict, Tuple

from app.db import get_db, utcnow
from app.services.config import settings
from app.services.crypto import decrypt_secret
from app.services.drive import (
    delete_old_files,
    ensure_branch_folders,
    get_drive_service,
    grant_branch_access,
    upload_file,
)
from app.services.mikrotik import MikroTikClient, normalize_export, sha256_text
from app.services.telegram import send_message


def parse_emails(raw: str) -> list[str]:
    return [email.strip() for email in raw.split(",") if email.strip()]


def parse_recipients(raw: str) -> list[str]:
    return [rid.strip() for rid in raw.split(",") if rid.strip()]


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
        username=router["username"],
        password=decrypt_secret(router["encrypted_password"]),
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
    branch_links = {}

    if needs_backup:
        stamp = now.strftime("%Y%m%dT%H%M%SZ")
        safe_name = router["name"].replace(" ", "_")
        backup_name = f"rv_{safe_name}_{stamp}.backup"
        rsc_name = f"rv_{safe_name}_{stamp}.rsc"

        backup_bytes = client.create_backup(backup_name)
        rsc_bytes = client.create_rsc_file(rsc_name)

        if settings.mock_mode and not settings.google_credentials:
            backup_link = f\"mock://drive/{backup_name}\"
            rsc_link = f\"mock://drive/{rsc_name}\"
        else:
            drive_service = get_drive_service()
            branch_id, branch_link, backups_id, rsc_id = ensure_branch_folders(
                drive_service, router["branch_name"]
            )
            emails = parse_emails(router.get("franchisee_emails") or "")
            grant_branch_access(drive_service, branch_id, emails)

            app_props = {"routervault": "true", "router": router["name"]}
            backup_link = upload_file(
                drive_service, backup_name, backup_bytes, backups_id, app_props=app_props
            )
            rsc_link = upload_file(
                drive_service, rsc_name, rsc_bytes, rsc_id, app_props=app_props
            )

            delete_old_files(drive_service, backups_id, router.get("retention_days") or 30)
            delete_old_files(drive_service, rsc_id, router.get("retention_days") or 30)

            branch_links = {
                "branch_folder_id": branch_id,
                "branch_folder_link": branch_link,
            }

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
        if branch_links:
            conn.execute(
                """
                UPDATE branches
                SET drive_folder_id = ?, drive_folder_link = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    branch_links["branch_folder_id"],
                    branch_links["branch_folder_link"],
                    utcnow(),
                    router["branch_id"],
                ),
            )

    if needs_backup:
        recipients = parse_recipients(router.get("telegram_recipients") or "")
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
            SELECT routers.*, branches.name AS branch_name,
                   branches.franchisee_emails,
                   branches.retention_days,
                   branches.telegram_recipients
            FROM routers
            JOIN branches ON branches.id = routers.branch_id
            WHERE routers.enabled = 1
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
