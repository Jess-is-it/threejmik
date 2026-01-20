import json
import secrets
from urllib.parse import quote
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_303_SEE_OTHER

from app.db import get_db, init_db, utcnow
from app.services.backup import run_router_check
from app.services.config import settings
from app.services.crypto import decrypt_secret, encrypt_secret
from app.services.drive import get_drive_service
from app.services.mikrotik import MikroTikClient, check_port
from app.services.scheduler import scheduler, start_scheduler
from app.services.telegram import send_message

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="RouterVault")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

templates = Jinja2Templates(directory=BASE_DIR / "templates")
security = HTTPBasic()


@app.on_event("startup")
def startup_event():
    init_db(settings.db_path)
    start_scheduler()


@app.on_event("shutdown")
def shutdown_event():
    if scheduler.running:
        scheduler.shutdown()


def require_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
    correct = secrets.compare_digest(credentials.username, settings.basic_user) and secrets.compare_digest(
        credentials.password, settings.basic_password
    )
    if not correct:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    return credentials.username


def format_ts(value: Optional[str]) -> str:
    if not value:
        return "-"
    return value


def is_stale(last_success: Optional[str], stale_days: int) -> bool:
    if not last_success:
        return True
    try:
        last_dt = datetime.fromisoformat(last_success)
    except ValueError:
        return True
    return datetime.utcnow() - last_dt >= timedelta(days=stale_days)


def parse_links(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def quote_message(message: str) -> str:
    return quote(str(message))


@app.get("/", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def dashboard(request: Request):
    with get_db(settings.db_path) as conn:
        routers = conn.execute(
            """
            SELECT routers.*, branches.name AS branch_name
            FROM routers
            JOIN branches ON branches.id = routers.branch_id
            ORDER BY routers.created_at DESC
            """
        ).fetchall()
        settings_row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
    stale_days = settings_row["stale_backup_days"] if settings_row else 3
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "routers": routers,
            "format_ts": format_ts,
            "is_stale": lambda ts: is_stale(ts, stale_days),
            "parse_links": parse_links,
            "stale_days": stale_days,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.get("/branches", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def list_branches(request: Request):
    with get_db(settings.db_path) as conn:
        branches = conn.execute("SELECT * FROM branches ORDER BY name").fetchall()
    return templates.TemplateResponse(
        "branches.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "branches": branches,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.get("/branches/{branch_id}", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def edit_branch(request: Request, branch_id: int):
    with get_db(settings.db_path) as conn:
        branch = conn.execute("SELECT * FROM branches WHERE id = ?", (branch_id,)).fetchone()
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found")
    return templates.TemplateResponse(
        "branch_edit.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "branch": branch,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/branches", dependencies=[Depends(require_basic_auth)])
def create_branch(
    name: str = Form(...),
    franchisee_emails: str = Form(""),
    drive_folder_id: str = Form(""),
    drive_folder_link: str = Form(""),
    retention_days: int = Form(30),
    telegram_recipients: str = Form(""),
):
    now = utcnow()
    with get_db(settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO branches
            (name, franchisee_emails, drive_folder_id, drive_folder_link, retention_days, telegram_recipients, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                franchisee_emails,
                drive_folder_id,
                drive_folder_link,
                retention_days,
                telegram_recipients,
                now,
                now,
            ),
        )
    return RedirectResponse("/branches?notice=branch_created", status_code=HTTP_303_SEE_OTHER)


@app.post("/branches/{branch_id}", dependencies=[Depends(require_basic_auth)])
def update_branch(
    branch_id: int,
    name: str = Form(...),
    franchisee_emails: str = Form(""),
    drive_folder_id: str = Form(""),
    drive_folder_link: str = Form(""),
    retention_days: int = Form(30),
    telegram_recipients: str = Form(""),
):
    with get_db(settings.db_path) as conn:
        conn.execute(
            """
            UPDATE branches
            SET name = ?, franchisee_emails = ?, drive_folder_id = ?, drive_folder_link = ?,
                retention_days = ?, telegram_recipients = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                name,
                franchisee_emails,
                drive_folder_id,
                drive_folder_link,
                retention_days,
                telegram_recipients,
                utcnow(),
                branch_id,
            ),
        )
    return RedirectResponse(f"/branches/{branch_id}?notice=branch_updated", status_code=HTTP_303_SEE_OTHER)


@app.post("/branches/{branch_id}/delete", dependencies=[Depends(require_basic_auth)])
def delete_branch(branch_id: int):
    with get_db(settings.db_path) as conn:
        conn.execute("DELETE FROM branches WHERE id = ?", (branch_id,))
    return RedirectResponse("/branches?notice=branch_deleted", status_code=HTTP_303_SEE_OTHER)


@app.post("/branches/{branch_id}/test-drive", dependencies=[Depends(require_basic_auth)])
def test_drive(branch_id: int):
    try:
        if not settings.mock_mode:
            get_drive_service()
        return RedirectResponse(f"/branches/{branch_id}?notice=drive_ok", status_code=HTTP_303_SEE_OTHER)
    except Exception as exc:
        return RedirectResponse(
            f"/branches/{branch_id}?error={quote_message(exc)}", status_code=HTTP_303_SEE_OTHER
        )


@app.post("/branches/{branch_id}/test-telegram", dependencies=[Depends(require_basic_auth)])
def test_telegram(branch_id: int):
    try:
        with get_db(settings.db_path) as conn:
            branch = conn.execute("SELECT * FROM branches WHERE id = ?", (branch_id,)).fetchone()
        if not branch:
            raise RuntimeError("Branch not found")
        recipients = [r.strip() for r in (branch["telegram_recipients"] or "").split(",") if r.strip()]
        if not recipients:
            raise RuntimeError("No telegram recipients set")
        send_message(recipients, "RouterVault test message")
        return RedirectResponse(f"/branches/{branch_id}?notice=telegram_ok", status_code=HTTP_303_SEE_OTHER)
    except Exception as exc:
        return RedirectResponse(
            f"/branches/{branch_id}?error={quote_message(exc)}", status_code=HTTP_303_SEE_OTHER
        )


@app.get("/routers", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def list_routers(request: Request):
    with get_db(settings.db_path) as conn:
        routers = conn.execute(
            """
            SELECT routers.*, branches.name AS branch_name
            FROM routers
            JOIN branches ON branches.id = routers.branch_id
            ORDER BY routers.created_at DESC
            """
        ).fetchall()
        branches = conn.execute("SELECT id, name FROM branches ORDER BY name").fetchall()
    return templates.TemplateResponse(
        "routers.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "routers": routers,
            "branches": branches,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.get("/routers/{router_id}", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def router_detail(request: Request, router_id: int, backup_id: Optional[int] = None):
    with get_db(settings.db_path) as conn:
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
        selected = None
        if backup_id:
            selected = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not selected and backups:
            selected = backups[0]
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    logs = []
    if selected and selected["logs"]:
        try:
            logs = json.loads(selected["logs"])
        except json.JSONDecodeError:
            logs = []
    return templates.TemplateResponse(
        "router_detail.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "router": router,
            "backups": backups,
            "selected": selected,
            "logs": logs,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.get("/routers/{router_id}/edit", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def edit_router(request: Request, router_id: int):
    with get_db(settings.db_path) as conn:
        router = conn.execute("SELECT * FROM routers WHERE id = ?", (router_id,)).fetchone()
        branches = conn.execute("SELECT id, name FROM branches ORDER BY name").fetchall()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    return templates.TemplateResponse(
        "router_edit.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "router": router,
            "branches": branches,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


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
    now = utcnow()
    with get_db(settings.db_path) as conn:
        conn.execute(
            """
            INSERT INTO routers
            (branch_id, name, ip, api_port, username, encrypted_password, enabled,
             backup_check_interval_hours, daily_baseline_time, force_backup_every_days,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                now,
                now,
            ),
        )
    return RedirectResponse("/routers?notice=router_created", status_code=HTTP_303_SEE_OTHER)


@app.post("/routers/{router_id}", dependencies=[Depends(require_basic_auth)])
def update_router(
    router_id: int,
    branch_id: int = Form(...),
    name: str = Form(...),
    ip: str = Form(...),
    api_port: int = Form(8728),
    username: str = Form(...),
    password: str = Form(""),
    enabled: Optional[str] = Form(None),
    backup_check_interval_hours: int = Form(6),
    daily_baseline_time: str = Form("02:00"),
    force_backup_every_days: int = Form(7),
):
    with get_db(settings.db_path) as conn:
        if password:
            conn.execute(
                """
                UPDATE routers
                SET branch_id = ?, name = ?, ip = ?, api_port = ?, username = ?, encrypted_password = ?, enabled = ?,
                    backup_check_interval_hours = ?, daily_baseline_time = ?, force_backup_every_days = ?, updated_at = ?
                WHERE id = ?
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
                    utcnow(),
                    router_id,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE routers
                SET branch_id = ?, name = ?, ip = ?, api_port = ?, username = ?, enabled = ?,
                    backup_check_interval_hours = ?, daily_baseline_time = ?, force_backup_every_days = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    branch_id,
                    name,
                    ip,
                    api_port,
                    username,
                    1 if enabled else 0,
                    backup_check_interval_hours,
                    daily_baseline_time,
                    force_backup_every_days,
                    utcnow(),
                    router_id,
                ),
            )
    return RedirectResponse(f"/routers/{router_id}/edit?notice=router_updated", status_code=HTTP_303_SEE_OTHER)


@app.post("/routers/{router_id}/delete", dependencies=[Depends(require_basic_auth)])
def delete_router(router_id: int):
    with get_db(settings.db_path) as conn:
        conn.execute("DELETE FROM routers WHERE id = ?", (router_id,))
    return RedirectResponse("/routers?notice=router_deleted", status_code=HTTP_303_SEE_OTHER)


@app.post("/routers/{router_id}/test", dependencies=[Depends(require_basic_auth)])
def test_router(router_id: int):
    with get_db(settings.db_path) as conn:
        router = conn.execute("SELECT * FROM routers WHERE id = ?", (router_id,)).fetchone()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    try:
        client = MikroTikClient(
            host=router["ip"],
            port=router["api_port"],
            username=router["username"],
            password=decrypt_secret(router["encrypted_password"]),
        )
        ok, message = client.test_connection()
        if not ok:
            ok, message = check_port(router["ip"], router["api_port"])
        return RedirectResponse(
            f"/routers/{router_id}?notice={'router_ok' if ok else 'router_fail'}&error={'' if ok else quote_message(message)}",
            status_code=HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            f"/routers/{router_id}?notice=router_fail&error={quote_message(exc)}",
            status_code=HTTP_303_SEE_OTHER,
        )


@app.post("/routers/{router_id}/backup", dependencies=[Depends(require_basic_auth)])
def trigger_backup(router_id: int):
    with get_db(settings.db_path) as conn:
        router = conn.execute(
            """
            SELECT routers.*, branches.name AS branch_name,
                   branches.franchisee_emails,
                   branches.retention_days,
                   branches.telegram_recipients
            FROM routers
            JOIN branches ON branches.id = routers.branch_id
            WHERE routers.id = ?
            """,
            (router_id,),
        ).fetchone()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    try:
        run_router_check(dict(router), baseline_due=True)
        return RedirectResponse(f"/routers/{router_id}?notice=backup_forced", status_code=HTTP_303_SEE_OTHER)
    except Exception as exc:
        return RedirectResponse(
            f"/routers/{router_id}?error={quote_message(exc)}", status_code=HTTP_303_SEE_OTHER
        )


@app.get("/settings", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def settings_page(request: Request):
    with get_db(settings.db_path) as conn:
        settings_row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "settings": settings_row,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/settings", dependencies=[Depends(require_basic_auth)])
def update_settings(stale_backup_days: int = Form(3)):
    with get_db(settings.db_path) as conn:
        conn.execute(
            "UPDATE settings SET stale_backup_days = ? WHERE id = 1",
            (stale_backup_days,),
        )
    return RedirectResponse("/settings?notice=settings_saved", status_code=HTTP_303_SEE_OTHER)


@app.get("/health")
def health():
    return {"status": "ok"}
