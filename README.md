# RouterVault

RouterVault is an auto-backup system for MikroTik RouterOS v7 with local storage, retention, Telegram notifications, config-change detection (hash + logs), and a server-rendered web UI.

## Quick Install (One Line)

On a new Debian/Ubuntu server, run:

```bash
curl -fsSL https://raw.githubusercontent.com/Jess-is-it/threejmik/master/install.sh | bash
```

The installer will:
- Install Docker + Docker Compose plugin (if missing)
- Prompt you for the initial username/password (first account is non-deletable)
- Clone RouterVault to `/opt/routervault`
- Build and start the service on port `8000` (and enable auto-start on reboot)

## Tech Stack
- Python 3.11
- FastAPI + Uvicorn
- Jinja2 templates (server-rendered HTML)
- Tabler UI kit (local assets)
- SQLite persisted to `/data/routervault.db`
- Backups persisted to `/data/storage`

## Local Development

1. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Run the server:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

3. Visit `http://localhost:8000` and log in (default `admin` / `changeme` unless you bootstrapped a different first account), then manage accounts in Settings → Authentication.

## Docker

```bash
docker compose up --build
```

The database will persist at `./data/routervault.db` via the compose volume.

## Project Layout
```
app/
  main.py
  db.py
  services/
  templates/
  static/
    tabler/
requirements.txt
Dockerfile
docker-compose.yml
```

## Environment Variables
- `ROUTERVAULT_DB_PATH` (default `/data/routervault.db`)
- `ROUTERVAULT_TELEGRAM_TOKEN`
- `ROUTERVAULT_SCHEDULER_INTERVAL` (seconds)
- `ROUTERVAULT_STORAGE_PATH` (default `/data/storage`)

## Notes
- Backups are stored per router at `/data/storage/<RouterName>/`.
- Background scheduler runs periodic router checks and baseline checks.
- Mock Mode is configured in the Settings page (simulates MikroTik operations for UI testing).
