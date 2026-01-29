import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable


def get_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path) -> None:
    with get_db(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                protected INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                api_port INTEGER DEFAULT 8728,
                api_timeout_seconds INTEGER DEFAULT 5,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                ftp_port INTEGER DEFAULT 21,
                enabled INTEGER DEFAULT 1,
                backup_check_interval_hours INTEGER DEFAULT 6,
                daily_baseline_time TEXT DEFAULT '02:00',
                force_backup_every_days INTEGER DEFAULT 7,
                retention_days INTEGER DEFAULT 30,
                telegram_recipients TEXT,
                last_log_check_at TEXT,
                last_backup_log_at TEXT,
                last_success_at TEXT,
                last_backup_at TEXT,
                last_backups_viewed_at TEXT,
                last_error TEXT,
                last_hash TEXT,
                last_config_change_at TEXT,
                last_backup_links TEXT,
                last_check_at TEXT,
                last_baseline_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                rsc_hash TEXT,
                rsc_link TEXT,
                backup_link TEXT,
                change_summary TEXT,
                logs TEXT,
                trigger TEXT DEFAULT 'auto',
                was_forced INTEGER DEFAULT 0,
                was_changed INTEGER DEFAULT 0,
                important INTEGER DEFAULT 0,
                FOREIGN KEY (router_id) REFERENCES routers (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS router_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_id INTEGER NOT NULL,
                logged_at TEXT NOT NULL,
                topics TEXT,
                message TEXT NOT NULL,
                backup_id INTEGER,
                created_at TEXT NOT NULL,
                FOREIGN KEY (router_id) REFERENCES routers (id) ON DELETE CASCADE,
                FOREIGN KEY (backup_id) REFERENCES backups (id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                router_id INTEGER,
                level TEXT DEFAULT 'info',
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                meta TEXT,
                sent_telegram INTEGER DEFAULT 0,
                viewed_at TEXT,
                FOREIGN KEY (router_id) REFERENCES routers (id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                stale_backup_days INTEGER DEFAULT 3,
                last_scheduler_run TEXT,
                telegram_token TEXT,
                telegram_recipients TEXT,
                alerts_retention_days INTEGER DEFAULT 30,
                telegram_notify_backup_created INTEGER DEFAULT 0,
                telegram_notify_backup_failed INTEGER DEFAULT 1,
                telegram_notify_router_recovered INTEGER DEFAULT 1,
                telegram_notify_manual_backup INTEGER DEFAULT 0,
                telegram_notify_restore INTEGER DEFAULT 1
            );
            INSERT OR IGNORE INTO settings (id, stale_backup_days) VALUES (1, 3);
            """
        )
        # Ensure schema upgrades for older DBs.
        user_columns = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "protected" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN protected INTEGER DEFAULT 0")

        # Ensure at least one UI user exists (bootstrap user is non-deletable).
        users_count = conn.execute("SELECT COUNT(1) AS c FROM users").fetchone()
        if users_count is None or int(users_count["c"] or 0) == 0:
            settings_row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
            row_dict = dict(settings_row) if settings_row else {}

            bootstrap_user = (os.getenv("ROUTERVAULT_BOOTSTRAP_USERNAME", "") or "").strip()
            bootstrap_pass = os.getenv("ROUTERVAULT_BOOTSTRAP_PASSWORD", "") or ""
            username = bootstrap_user or (row_dict.get("basic_user") or "admin")
            password = bootstrap_pass or (row_dict.get("basic_password") or "changeme")
            username = (username or "admin").strip() or "admin"
            password = password or "changeme"

            now = utcnow()
            conn.execute(
                """
                INSERT OR IGNORE INTO users (username, password, protected, enabled, created_at, updated_at)
                VALUES (?, ?, 1, 1, ?, ?)
                """,
                (username, password, now, now),
            )
        else:
            # If a DB already has users but none marked protected, protect the oldest one.
            has_protected = conn.execute("SELECT COUNT(1) AS c FROM users WHERE protected = 1").fetchone()
            if has_protected is None or int(has_protected["c"] or 0) == 0:
                oldest = conn.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
                if oldest:
                    conn.execute("UPDATE users SET protected = 1 WHERE id = ?", (int(oldest["id"]),))
        columns = [row[1] for row in conn.execute("PRAGMA table_info(routers)").fetchall()]
        needs_migration = any(
            col in columns
            for col in (
                "branch_id",
                "franchisee_emails",
                "drive_folder_id",
                "drive_folder_link",
            )
        ) or "ftp_port" not in columns or "api_timeout_seconds" not in columns
        if needs_migration:
            conn.executescript(
                """
                CREATE TABLE routers_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    api_port INTEGER DEFAULT 8728,
                    api_timeout_seconds INTEGER DEFAULT 5,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    ftp_port INTEGER DEFAULT 21,
                    enabled INTEGER DEFAULT 1,
                    backup_check_interval_hours INTEGER DEFAULT 6,
                    daily_baseline_time TEXT DEFAULT '02:00',
                    force_backup_every_days INTEGER DEFAULT 7,
                    retention_days INTEGER DEFAULT 30,
                    telegram_recipients TEXT,
                    last_log_check_at TEXT,
                    last_backup_log_at TEXT,
                    last_success_at TEXT,
                    last_backup_at TEXT,
                    last_backups_viewed_at TEXT,
                    last_error TEXT,
                    last_hash TEXT,
                    last_config_change_at TEXT,
                    last_backup_links TEXT,
                    last_check_at TEXT,
                    last_baseline_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            retention_expr = "retention_days" if "retention_days" in columns else "30"
            telegram_expr = "telegram_recipients" if "telegram_recipients" in columns else "''"
            api_timeout_expr = "api_timeout_seconds" if "api_timeout_seconds" in columns else "5"
            ftp_port_expr = "ftp_port" if "ftp_port" in columns else "21"

            conn.execute(
                f"""
                INSERT INTO routers_new (
                    id, name, ip, api_port, api_timeout_seconds, username, encrypted_password, ftp_port, enabled,
                    backup_check_interval_hours, daily_baseline_time, force_backup_every_days,
                    retention_days, telegram_recipients,
                    last_log_check_at, last_backup_log_at, last_success_at, last_backup_at, last_error,
                    last_hash, last_config_change_at, last_backup_links,
                    last_check_at, last_baseline_at, created_at, updated_at
                )
                SELECT
                    id, name, ip, api_port, {api_timeout_expr}, username, encrypted_password, {ftp_port_expr}, enabled,
                    backup_check_interval_hours, daily_baseline_time, force_backup_every_days,
                    {retention_expr}, {telegram_expr},
                    last_log_check_at,
                    COALESCE(last_log_check_at, last_success_at),
                    last_success_at, last_backup_at, last_success_at,
                    last_error,
                    last_hash, last_config_change_at, last_backup_links,
                    last_check_at, last_baseline_at, created_at, updated_at
                FROM routers
                """
            )
            conn.execute("DROP TABLE routers")
            conn.execute("ALTER TABLE routers_new RENAME TO routers")
            conn.execute("DROP TABLE IF EXISTS branches")
        routers_columns = [row[1] for row in conn.execute("PRAGMA table_info(routers)").fetchall()]
        if "last_backup_log_at" not in routers_columns:
            conn.execute("ALTER TABLE routers ADD COLUMN last_backup_log_at TEXT")
            conn.execute(
                """
                UPDATE routers
                SET last_backup_log_at = COALESCE(last_log_check_at, last_success_at)
                WHERE last_backup_log_at IS NULL
                """
            )
        if "last_backups_viewed_at" not in routers_columns:
            conn.execute("ALTER TABLE routers ADD COLUMN last_backups_viewed_at TEXT")
            conn.execute(
                """
                UPDATE routers
                SET last_backups_viewed_at = COALESCE(last_backup_at, last_success_at, last_check_at, created_at)
                WHERE last_backups_viewed_at IS NULL
                """
            )
        settings_columns = [row[1] for row in conn.execute("PRAGMA table_info(settings)").fetchall()]
        backups_columns = [row[1] for row in conn.execute("PRAGMA table_info(backups)").fetchall()]
        alerts_columns = [row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()]
        if "trigger" not in backups_columns:
            conn.execute("ALTER TABLE backups ADD COLUMN trigger TEXT DEFAULT 'auto'")
        conn.execute("UPDATE backups SET trigger = 'auto' WHERE trigger IS NULL OR trigger = ''")
        if "important" not in backups_columns:
            conn.execute("ALTER TABLE backups ADD COLUMN important INTEGER DEFAULT 0")
            conn.execute("UPDATE backups SET important = 0 WHERE important IS NULL")
        if not alerts_columns:
            # Older DBs created before alerts existed.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    router_id INTEGER,
                    level TEXT DEFAULT 'info',
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    meta TEXT,
                    sent_telegram INTEGER DEFAULT 0,
                    viewed_at TEXT,
                    FOREIGN KEY (router_id) REFERENCES routers (id) ON DELETE SET NULL
                )
                """
            )
        if "telegram_token" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_token TEXT")
        if "telegram_recipients" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_recipients TEXT")
        if "alerts_retention_days" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN alerts_retention_days INTEGER DEFAULT 30")
        if "telegram_notify_backup_created" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_notify_backup_created INTEGER DEFAULT 0")
        if "telegram_notify_backup_failed" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_notify_backup_failed INTEGER DEFAULT 1")
        if "telegram_notify_router_recovered" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_notify_router_recovered INTEGER DEFAULT 1")
        if "telegram_notify_manual_backup" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_notify_manual_backup INTEGER DEFAULT 0")
        if "telegram_notify_restore" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_notify_restore INTEGER DEFAULT 1")
        if "basic_user" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN basic_user TEXT")
        if "basic_password" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN basic_password TEXT")
        if "mock_mode" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN mock_mode INTEGER DEFAULT 0")
        if "export_show_sensitive" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN export_show_sensitive INTEGER DEFAULT 0")

        conn.execute(
            """
            UPDATE settings
            SET basic_user = COALESCE(NULLIF(basic_user, ''), 'admin'),
                basic_password = COALESCE(NULLIF(basic_password, ''), 'changeme'),
                mock_mode = COALESCE(mock_mode, 0),
                export_show_sensitive = COALESCE(export_show_sensitive, 0),
                alerts_retention_days = COALESCE(alerts_retention_days, 30),
                telegram_notify_backup_created = COALESCE(telegram_notify_backup_created, 0),
                telegram_notify_backup_failed = COALESCE(telegram_notify_backup_failed, 1),
                telegram_notify_router_recovered = COALESCE(telegram_notify_router_recovered, 1),
                telegram_notify_manual_backup = COALESCE(telegram_notify_manual_backup, 0),
                telegram_notify_restore = COALESCE(telegram_notify_restore, 1)
            WHERE id = 1
            """
        )


def utcnow() -> str:
    return datetime.utcnow().isoformat()


def rows_to_list(rows: Iterable[sqlite3.Row]):
    return [dict(row) for row in rows]
