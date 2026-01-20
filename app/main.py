import base64
import os
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.status import HTTP_303_SEE_OTHER

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("ROUTERVAULT_DB_PATH", "/data/routervault.db"))

app = FastAPI(title="RouterVault")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

security = HTTPBasic()


def get_env(name: str, default: Optional[str] = None, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


TEMPLATES = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


@app.middleware("http")
async def add_template_globals(request: Request, call_next):
    request.state.template_globals = {
        "request": request,
        "app_name": "RouterVault",
    }
    return await call_next(request)


def render(template_name: str, **context):
    template = TEMPLATES.get_template(template_name)
    base_context = context.pop("_base", {})
    return template.render(**base_context, **context)


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
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
                created_at TEXT NOT NULL
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
                created_at TEXT NOT NULL,
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
                FOREIGN KEY (router_id) REFERENCES routers (id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                stale_backup_days INTEGER DEFAULT 3
            );
            INSERT OR IGNORE INTO settings (id, stale_backup_days) VALUES (1, 3);
            """
        )


@app.on_event("startup")
def startup_event():
    init_db()


def get_fernet() -> Fernet:
    raw = get_env("ROUTERVAULT_ENCRYPTION_KEY", required=True)
    try:
        key = raw.encode("utf-8")
        if len(key) != 44:
            key = base64.urlsafe_b64encode(key)
        return Fernet(key)
    except Exception as exc:
        raise RuntimeError("Invalid encryption key") from exc


def encrypt_secret(value: str) -> str:
    return get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    try:
        return get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""


def require_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    username = get_env("ROUTERVAULT_BASIC_USER", "admin")
    password = get_env("ROUTERVAULT_BASIC_PASSWORD", "changeme")
    correct = secrets.compare_digest(credentials.username, username) and secrets.compare_digest(
        credentials.password, password
    )
    if not correct:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def format_ts(value: Optional[str]) -> str:
    if not value:
        return "-"
    return value


@app.get("/", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def dashboard(request: Request):
    with get_db() as conn:
        routers = conn.execute(
            """
            SELECT routers.*, branches.name AS branch_name
            FROM routers
            JOIN branches ON branches.id = routers.branch_id
            ORDER BY routers.created_at DESC
            """
        ).fetchall()
    body = render(
        "dashboard.html",
        _base=request.state.template_globals,
        routers=routers,
        format_ts=format_ts,
    )
    return HTMLResponse(body)


@app.get("/branches", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def list_branches(request: Request):
    with get_db() as conn:
        branches = conn.execute("SELECT * FROM branches ORDER BY name").fetchall()
    body = render(
        "branches.html",
        _base=request.state.template_globals,
        branches=branches,
    )
    return HTMLResponse(body)


@app.post("/branches", dependencies=[Depends(require_basic_auth)])
def create_branch(
    name: str = Form(...),
    franchisee_emails: str = Form(""),
    drive_folder_id: str = Form(""),
    drive_folder_link: str = Form(""),
    retention_days: int = Form(30),
    telegram_recipients: str = Form(""),
):
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO branches
            (name, franchisee_emails, drive_folder_id, drive_folder_link, retention_days, telegram_recipients, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                franchisee_emails,
                drive_folder_id,
                drive_folder_link,
                retention_days,
                telegram_recipients,
                datetime.utcnow().isoformat(),
            ),
        )
    return RedirectResponse("/branches", status_code=HTTP_303_SEE_OTHER)


@app.post("/branches/{branch_id}/delete", dependencies=[Depends(require_basic_auth)])
def delete_branch(branch_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM branches WHERE id = ?", (branch_id,))
    return RedirectResponse("/branches", status_code=HTTP_303_SEE_OTHER)


@app.get("/routers", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def list_routers(request: Request):
    with get_db() as conn:
        routers = conn.execute(
            """
            SELECT routers.*, branches.name AS branch_name
            FROM routers
            JOIN branches ON branches.id = routers.branch_id
            ORDER BY routers.created_at DESC
            """
        ).fetchall()
        branches = conn.execute("SELECT id, name FROM branches ORDER BY name").fetchall()
    body = render(
        "routers.html",
        _base=request.state.template_globals,
        routers=routers,
        branches=branches,
    )
    return HTMLResponse(body)


@app.post("/routers", dependencies=[Depends(require_basic_auth)])
def create_router(
    branch_id: int = Form(...),
    name: str = Form(...),
    ip: str = Form(...),
    api_port: int = Form(8728),
    username: str = Form(...),
    password: str = Form(...),
    enabled: Optional[str] = Form(None),
    backup_check_interval_hours: int = Form(6),
    daily_baseline_time: str = Form("02:00"),
    force_backup_every_days: int = Form(7),
):
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO routers
            (branch_id, name, ip, api_port, username, encrypted_password, enabled,
             backup_check_interval_hours, daily_baseline_time, force_backup_every_days,
             created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                branch_id,
                name,
                ip,
                api_port,
                username,
                encrypt_secret(password),
                1 if enabled else 0,
                backup_check_interval_hours,
                daily_baseline_time,
                force_backup_every_days,
                datetime.utcnow().isoformat(),
            ),
        )
    return RedirectResponse("/routers", status_code=HTTP_303_SEE_OTHER)


@app.post("/routers/{router_id}/delete", dependencies=[Depends(require_basic_auth)])
def delete_router(router_id: int):
    with get_db() as conn:
        conn.execute("DELETE FROM routers WHERE id = ?", (router_id,))
    return RedirectResponse("/routers", status_code=HTTP_303_SEE_OTHER)


@app.get("/routers/{router_id}", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def router_detail(request: Request, router_id: int):
    with get_db() as conn:
        router = conn.execute(
            """
            SELECT routers.*, branches.name AS branch_name
            FROM routers
            JOIN branches ON branches.id = routers.branch_id
            WHERE routers.id = ?
            """,
            (router_id,),
        ).fetchone()
        backups = conn.execute(
            """
            SELECT * FROM backups
            WHERE router_id = ?
            ORDER BY created_at DESC
            """,
            (router_id,),
        ).fetchall()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    body = render(
        "router_detail.html",
        _base=request.state.template_globals,
        router=router,
        backups=backups,
    )
    return HTMLResponse(body)


@app.post("/routers/{router_id}/test", dependencies=[Depends(require_basic_auth)])
def test_router(router_id: int):
    with get_db() as conn:
        router = conn.execute("SELECT * FROM routers WHERE id = ?", (router_id,)).fetchone()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    return RedirectResponse(f"/routers/{router_id}?test=ok", status_code=HTTP_303_SEE_OTHER)


@app.post("/branches/{branch_id}/test-drive", dependencies=[Depends(require_basic_auth)])
def test_drive(branch_id: int):
    return RedirectResponse(f"/branches?drive_test={branch_id}", status_code=HTTP_303_SEE_OTHER)


@app.post("/branches/{branch_id}/test-telegram", dependencies=[Depends(require_basic_auth)])
def test_telegram(branch_id: int):
    return RedirectResponse(f"/branches?telegram_test={branch_id}", status_code=HTTP_303_SEE_OTHER)


@app.get("/settings", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def settings_page(request: Request):
    with get_db() as conn:
        settings = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
    body = render(
        "settings.html",
        _base=request.state.template_globals,
        settings=settings,
    )
    return HTMLResponse(body)


@app.post("/settings", dependencies=[Depends(require_basic_auth)])
def update_settings(stale_backup_days: int = Form(3)):
    with get_db() as conn:
        conn.execute("UPDATE settings SET stale_backup_days = ? WHERE id = 1", (stale_backup_days,))
    return RedirectResponse("/settings", status_code=HTTP_303_SEE_OTHER)


@app.get("/health")
def health():
    return {"status": "ok"}
