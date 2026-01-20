import httpx

from app.services.config import settings


def send_message(chat_ids: list[str], message: str) -> None:
    if settings.mock_mode:
        return
    if not settings.telegram_token:
        raise RuntimeError("Missing ROUTERVAULT_TELEGRAM_TOKEN")
    url = f"https://api.telegram.org/bot{settings.telegram_token}/sendMessage"
    with httpx.Client(timeout=10) as client:
        for chat_id in chat_ids:
            if not chat_id:
                continue
            client.post(url, json={"chat_id": chat_id, "text": message})
