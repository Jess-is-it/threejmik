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
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                stale_backup_days INTEGER DEFAULT 3,
                last_scheduler_run TEXT,
                telegram_token TEXT,
                telegram_recipients TEXT
            );
            INSERT OR IGNORE INTO settings (id, stale_backup_days) VALUES (1, 3);
            """
        )
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
                    last_success_at, last_backup_at, last_error,
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
        settings_columns = [row[1] for row in conn.execute("PRAGMA table_info(settings)").fetchall()]
        backups_columns = [row[1] for row in conn.execute("PRAGMA table_info(backups)").fetchall()]
        if "trigger" not in backups_columns:
            conn.execute("ALTER TABLE backups ADD COLUMN trigger TEXT DEFAULT 'auto'")
        if "telegram_token" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_token TEXT")
        if "telegram_recipients" not in settings_columns:
            conn.execute("ALTER TABLE settings ADD COLUMN telegram_recipients TEXT")
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
                export_show_sensitive = COALESCE(export_show_sensitive, 0)
            WHERE id = 1
            """
        )


def utcnow() -> str:
    return datetime.utcnow().isoformat()


def rows_to_list(rows: Iterable[sqlite3.Row]):
    return [dict(row) for row in rows]
