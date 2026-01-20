import os
from pathlib import Path
from typing import Optional


class Settings:
    def __init__(self) -> None:
        self.db_path = Path(os.getenv("ROUTERVAULT_DB_PATH", "/data/routervault.db"))
        self.basic_user = os.getenv("ROUTERVAULT_BASIC_USER", "admin")
        self.basic_password = os.getenv("ROUTERVAULT_BASIC_PASSWORD", "changeme")
        self.encryption_key = os.getenv("ROUTERVAULT_ENCRYPTION_KEY", "")
        self.google_credentials = os.getenv("ROUTERVAULT_GOOGLE_CREDENTIALS", "")
        self.telegram_token = os.getenv("ROUTERVAULT_TELEGRAM_TOKEN", "")
        self.mock_mode = os.getenv("ROUTERVAULT_MOCK_MODE", "false").lower() in (
            "1",
            "true",
            "yes",
        )
        self.log_keywords = [
            keyword.strip().lower()
            for keyword in os.getenv(
                "ROUTERVAULT_LOG_KEYWORDS", "config,configuration,change,changed,script"
            ).split(",")
            if keyword.strip()
        ]
        self.scheduler_interval_seconds = int(
            os.getenv("ROUTERVAULT_SCHEDULER_INTERVAL", "300")
        )

    def require_env(self, name: str) -> str:
        value = os.getenv(name, "")
        if not value:
            raise RuntimeError(f"Missing required env var: {name}")
        return value


settings = Settings()
