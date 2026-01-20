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
            CREATE TABLE IF NOT EXISTS branches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                franchisee_emails TEXT,
                drive_folder_id TEXT,
                drive_folder_link TEXT,
                retention_days INTEGER DEFAULT 30,
                telegram_recipients TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS routers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                branch_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                api_port INTEGER DEFAULT 8728,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                backup_check_interval_hours INTEGER DEFAULT 6,
                daily_baseline_time TEXT DEFAULT '02:00',
                force_backup_every_days INTEGER DEFAULT 7,
                last_log_check_at TEXT,
                last_success_at TEXT,
                last_backup_at TEXT,
                last_error TEXT,
                last_hash TEXT,
                last_config_change_at TEXT,
                last_backup_links TEXT,
                last_check_at TEXT,
                last_baseline_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (branch_id) REFERENCES branches (id) ON DELETE CASCADE
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
                last_scheduler_run TEXT
            );
            INSERT OR IGNORE INTO settings (id, stale_backup_days) VALUES (1, 3);
            """
        )


def utcnow() -> str:
    return datetime.utcnow().isoformat()


def rows_to_list(rows: Iterable[sqlite3.Row]):
    return [dict(row) for row in rows]
