import httpx

from app.db import get_db
from app.services.config import settings


def get_telegram_token() -> str:
    with get_db(settings.db_path) as conn:
        row = conn.execute("SELECT telegram_token FROM settings WHERE id = 1").fetchone()
    return row["telegram_token"] if row and row["telegram_token"] else settings.telegram_token


def get_default_recipients() -> list[str]:
    with get_db(settings.db_path) as conn:
        row = conn.execute("SELECT telegram_recipients FROM settings WHERE id = 1").fetchone()
    raw = row["telegram_recipients"] if row and row["telegram_recipients"] else ""
    return [value.strip() for value in raw.split(",") if value.strip()]


def send_message(chat_ids: list[str], message: str) -> None:
    if settings.mock_mode:
        return
    token = get_telegram_token()
    if not token:
        raise RuntimeError("Missing Telegram token")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    with httpx.Client(timeout=10) as client:
        for chat_id in chat_ids:
            if not chat_id:
                continue
            client.post(url, json={"chat_id": chat_id, "text": message})
