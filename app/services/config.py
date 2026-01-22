import os
from pathlib import Path
from typing import Optional


class Settings:
    def __init__(self) -> None:
        self.db_path = Path(os.getenv("ROUTERVAULT_DB_PATH", "/data/routervault.db"))
        self.storage_path = Path(os.getenv("ROUTERVAULT_STORAGE_PATH", "/data/storage"))
        self.telegram_token = os.getenv("ROUTERVAULT_TELEGRAM_TOKEN", "")
        self.scheduler_interval_seconds = int(
            os.getenv("ROUTERVAULT_SCHEDULER_INTERVAL", "300")
        )

    def require_env(self, name: str) -> str:
        value = os.getenv(name, "")
        if not value:
            raise RuntimeError(f"Missing required env var: {name}")
        return value


settings = Settings()
