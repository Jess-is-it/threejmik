import json
from datetime import datetime, timedelta
from typing import Any, Optional

from app.db import get_db, utcnow
from app.services.config import settings
from app.services.telegram import get_default_recipients, send_message


def _get_settings_flags() -> dict[str, Any]:
    with get_db(settings.db_path) as conn:
        row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
    return dict(row) if row is not None else {}


def should_send_telegram(kind: str) -> bool:
    flags = _get_settings_flags()
    mapping = {
        "backup_created": bool(flags.get("telegram_notify_backup_created") or 0),
        "backup_failed": bool(flags.get("telegram_notify_backup_failed") or 0),
        "router_recovered": bool(flags.get("telegram_notify_router_recovered") or 0),
        "manual_backup": bool(flags.get("telegram_notify_manual_backup") or 0),
        "restore": bool(flags.get("telegram_notify_restore") or 0),
    }
    return bool(mapping.get(kind, False))


def get_alert_retention_days() -> int:
    flags = _get_settings_flags()
    try:
        days = int(flags.get("alerts_retention_days") or 30)
    except Exception:
        days = 30
    return max(1, days)


def cleanup_old_alerts() -> None:
    days = get_alert_retention_days()
    cutoff = datetime.utcnow() - timedelta(days=days)
    cutoff_str = cutoff.isoformat()
    with get_db(settings.db_path) as conn:
        conn.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff_str,))


def mark_all_alerts_viewed() -> tuple[int, int]:
    now = utcnow()
    with get_db(settings.db_path) as conn:
        conn.execute("UPDATE alerts SET viewed_at = ? WHERE viewed_at IS NULL", (now,))
        total = conn.execute("SELECT COUNT(1) AS c FROM alerts").fetchone()
        viewed = conn.execute("SELECT COUNT(1) AS c FROM alerts WHERE viewed_at IS NOT NULL").fetchone()
    return int(viewed["c"] or 0), int(total["c"] or 0)


def create_alert(
    *,
    router_id: Optional[int],
    level: str,
    kind: str,
    title: str,
    message: str,
    meta: Optional[dict[str, Any]] = None,
    dedupe_seconds: int = 0,
) -> int | None:
    meta_text = json.dumps(meta or {})
    created_at = utcnow()

    if dedupe_seconds > 0:
        try:
            cutoff = (datetime.utcnow() - timedelta(seconds=dedupe_seconds)).isoformat()
        except Exception:
            cutoff = ""
        with get_db(settings.db_path) as conn:
            exists = conn.execute(
                """
                SELECT id
                FROM alerts
                WHERE router_id IS ?
                  AND kind = ?
                  AND message = ?
                  AND created_at >= ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (router_id, kind, message, cutoff),
            ).fetchone()
        if exists:
            return int(exists["id"])

    with get_db(settings.db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts (created_at, router_id, level, kind, title, message, meta, sent_telegram, viewed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL)
            """,
            (created_at, router_id, level, kind, title, message, meta_text),
        )
        alert_id = int(cursor.lastrowid)

    if should_send_telegram(kind):
        recipients = get_default_recipients()
        if recipients:
            telegram_text = f"{title}\n{message}"
            try:
                send_message(recipients, telegram_text)
                with get_db(settings.db_path) as conn:
                    conn.execute("UPDATE alerts SET sent_telegram = 1 WHERE id = ?", (alert_id,))
            except Exception:
                # Don't interrupt backups/scheduler for notification failures.
                pass

    return alert_id

