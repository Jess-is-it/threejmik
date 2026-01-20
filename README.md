# RouterVault

RouterVault is an auto-backup system for MikroTik RouterOS v7 with Google Drive storage, retention, Telegram notifications, config-change detection (hash + logs), and a server-rendered web UI.

## Tech Stack
- Python 3.11
- FastAPI + Uvicorn
- Jinja2 templates (server-rendered HTML)
- Tabler UI kit (local assets)
- SQLite persisted to `/data/routervault.db`

## Local Development

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Create `.env` from `.env.example` and set a strong encryption key:
   ```bash
   cp .env.example .env
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   Paste the generated key into `ROUTERVAULT_ENCRYPTION_KEY`.

3. Run the server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

4. Visit `http://localhost:8000` and log in with the basic auth credentials from `.env`.

## Docker

```bash
docker compose up --build
```

The database will persist at `./data/routervault.db` via the compose volume.

## Project Layout
```
app/
  main.py
  templates/
  static/
    tabler/
requirements.txt
Dockerfile
docker-compose.yml
```

## Environment Variables
- `ROUTERVAULT_BASIC_USER`
- `ROUTERVAULT_BASIC_PASSWORD`
- `ROUTERVAULT_ENCRYPTION_KEY`
- `ROUTERVAULT_DB_PATH` (default `/data/routervault.db`)
- `ROUTERVAULT_GOOGLE_CREDENTIALS`
- `ROUTERVAULT_TELEGRAM_TOKEN`

## Notes
- Router passwords are encrypted at rest in SQLite using `ROUTERVAULT_ENCRYPTION_KEY`.
- The UI includes branches, routers, backups, and settings pages with stubbed test actions.
