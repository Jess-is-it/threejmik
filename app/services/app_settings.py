from __future__ import annotations

from dataclasses import dataclass

from app.db import get_db
from app.services.config import settings


@dataclass(frozen=True)
class AppSettings:
    mock_mode: bool
    export_show_sensitive: bool


def load_app_settings() -> AppSettings:
    with get_db(settings.db_path) as conn:
        row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()

    mock_mode = False
    export_show_sensitive = False

    if row is not None:
        row_dict = dict(row)
        mock_mode = bool(row_dict.get("mock_mode") or 0)
        export_show_sensitive = bool(row_dict.get("export_show_sensitive") or 0)

    return AppSettings(
        mock_mode=mock_mode,
        export_show_sensitive=export_show_sensitive,
    )


def is_mock_mode() -> bool:
    return load_app_settings().mock_mode


def export_show_sensitive() -> bool:
    return load_app_settings().export_show_sensitive
