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
from app.services.mikrotik import MikroTikClient, check_port
from app.services.scheduler import scheduler, start_scheduler
from app.services.telegram import send_message

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="RouterVault")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
settings.storage_path.mkdir(parents=True, exist_ok=True)
app.mount("/storage", StaticFiles(directory=settings.storage_path), name="storage")

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
            SELECT *
            FROM routers
            ORDER BY created_at DESC
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


@app.get("/routers", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def list_routers(request: Request):
    with get_db(settings.db_path) as conn:
        routers = conn.execute(
            """
            SELECT *
            FROM routers
            ORDER BY created_at DESC
            """
        ).fetchall()
    return templates.TemplateResponse(
        "routers.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "routers": routers,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.get("/backups", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def list_backups(request: Request):
    with get_db(settings.db_path) as conn:
        backups = conn.execute(
            """
            SELECT backups.*, routers.name AS router_name, routers.ip, routers.api_port
            FROM backups
            JOIN routers ON routers.id = backups.router_id
            ORDER BY backups.created_at DESC
            """
        ).fetchall()
    parsed = []
    for backup in backups:
        logs_text = ""
        if backup["logs"]:
            try:
                entries = json.loads(backup["logs"])
                logs_text = "\n".join(
                    f"{entry.get('logged_at','')} {entry.get('topics','')} {entry.get('message','')}"
                    for entry in entries
                )
            except json.JSONDecodeError:
                logs_text = backup["logs"]
        parsed.append({**dict(backup), "logs_text": logs_text})
    return templates.TemplateResponse(
        "backups.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "backups": parsed,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


def _link_to_path(link: str) -> Path:
    if not link or not link.startswith("/storage/"):
        return Path()
    relative = link[len("/storage/") :]
    return settings.storage_path / relative


@app.post("/backups/{backup_id}/delete", dependencies=[Depends(require_basic_auth)])
def delete_backup(backup_id: int):
    with get_db(settings.db_path) as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")
        backup_path = _link_to_path(backup["backup_link"] or "")
        rsc_path = _link_to_path(backup["rsc_link"] or "")
        if backup_path.exists():
            backup_path.unlink()
        if rsc_path.exists():
            rsc_path.unlink()
        conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
    return RedirectResponse("/backups?notice=backup_deleted", status_code=HTTP_303_SEE_OTHER)


@app.post("/backups/{backup_id}/restore", dependencies=[Depends(require_basic_auth)])
def restore_backup(backup_id: int):
    with get_db(settings.db_path) as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")
        router = conn.execute("SELECT * FROM routers WHERE id = ?", (backup["router_id"],)).fetchone()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    backup_path = _link_to_path(backup["backup_link"] or "")
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup file missing")
    try:
        client = MikroTikClient(
            host=router["ip"],
            port=router["api_port"],
            timeout=router.get("api_timeout_seconds") or 5,
            username=router["username"],
            password=router["encrypted_password"],
            ftp_port=router.get("ftp_port") or 21,
        )
        client.restore_backup(backup_path.name, backup_path.read_bytes())
        return RedirectResponse("/backups?notice=restore_started", status_code=HTTP_303_SEE_OTHER)
    except Exception as exc:
        return RedirectResponse(f"/backups?error={quote_message(exc)}", status_code=HTTP_303_SEE_OTHER)


@app.post("/routers/presets", dependencies=[Depends(require_basic_auth)])
async def update_router_presets(request: Request):
    form = await request.form()
    updates = []
    for key, value in form.items():
        if not key.startswith("router_id_"):
            continue
        router_id = int(value)
        retention_days = int(form.get(f"retention_days_{router_id}", 30))
        backup_check_interval_hours = int(form.get(f"backup_check_interval_hours_{router_id}", 6))
        daily_baseline_time = form.get(f"daily_baseline_time_{router_id}", "02:00")
        force_backup_every_days = int(form.get(f"force_backup_every_days_{router_id}", 7))
        enabled_value = form.get(f"enabled_{router_id}", "1")
        enabled = 1 if enabled_value == "1" else 0
        updates.append(
            (
                retention_days,
                backup_check_interval_hours,
                daily_baseline_time,
                force_backup_every_days,
                enabled,
                utcnow(),
                router_id,
            )
        )
    if updates:
        with get_db(settings.db_path) as conn:
            conn.executemany(
                """
                UPDATE routers
                SET retention_days = ?,
                    backup_check_interval_hours = ?,
                    daily_baseline_time = ?,
                    force_backup_every_days = ?,
                    enabled = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                updates,
            )
    return RedirectResponse("/routers?notice=presets_saved", status_code=HTTP_303_SEE_OTHER)


@app.get("/routers/{router_id}", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def router_detail(request: Request, router_id: int, backup_id: Optional[int] = None):
    with get_db(settings.db_path) as conn:
        router = conn.execute(
            """
            SELECT *
            FROM routers
            WHERE id = ?
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
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    return templates.TemplateResponse(
        "router_edit.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "router": router,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/routers", dependencies=[Depends(require_basic_auth)])
def create_router(
    name: str = Form(...),
    ip: str = Form(...),
    api_port: int = Form(8728),
    api_timeout_seconds: int = Form(5),
    username: str = Form(...),
    password: str = Form(...),
    ftp_port: int = Form(21),
    retention_days: int = Form(30),
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
            (name, ip, api_port, api_timeout_seconds, username, encrypted_password, ftp_port, enabled,
             backup_check_interval_hours, daily_baseline_time, force_backup_every_days,
             retention_days, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                ip,
                api_port,
                api_timeout_seconds,
                username,
                password,
                ftp_port,
                1 if enabled else 0,
                backup_check_interval_hours,
                daily_baseline_time,
                force_backup_every_days,
                retention_days,
                now,
                now,
            ),
        )
    return RedirectResponse("/routers?notice=router_created", status_code=HTTP_303_SEE_OTHER)


@app.post("/routers/test-draft", dependencies=[Depends(require_basic_auth)])
def test_router_draft(
    ip: str = Form(...),
    api_port: int = Form(8728),
    api_timeout_seconds: int = Form(5),
    username: str = Form(...),
    password: str = Form(...),
    ftp_port: int = Form(21),
):
    try:
        client = MikroTikClient(
            host=ip,
            port=api_port,
            timeout=api_timeout_seconds or 5,
            username=username,
            password=password,
            ftp_port=ftp_port or 21,
        )
        ok, message = client.test_connection()
        if not ok:
            ok, message = check_port(ip, api_port)
        return RedirectResponse(
            f"/routers?notice={'router_ok' if ok else 'router_fail'}&error={'' if ok else quote_message(message)}",
            status_code=HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            f"/routers?notice=router_fail&error={quote_message(exc)}",
            status_code=HTTP_303_SEE_OTHER,
        )


@app.post("/routers/{router_id}", dependencies=[Depends(require_basic_auth)])
def update_router(
    router_id: int,
    name: str = Form(...),
    ip: str = Form(...),
    api_port: int = Form(8728),
    api_timeout_seconds: int = Form(5),
    username: str = Form(...),
    password: str = Form(""),
    ftp_port: int = Form(21),
    retention_days: int = Form(30),
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
                SET name = ?, ip = ?, api_port = ?, api_timeout_seconds = ?, username = ?, encrypted_password = ?, ftp_port = ?, enabled = ?,
                    backup_check_interval_hours = ?, daily_baseline_time = ?, force_backup_every_days = ?,
                    retention_days = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    name,
                    ip,
                    api_port,
                    api_timeout_seconds,
                    username,
                    password,
                    ftp_port,
                    1 if enabled else 0,
                    backup_check_interval_hours,
                    daily_baseline_time,
                    force_backup_every_days,
                    retention_days,
                    utcnow(),
                    router_id,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE routers
                SET name = ?, ip = ?, api_port = ?, api_timeout_seconds = ?, username = ?, ftp_port = ?, enabled = ?,
                    backup_check_interval_hours = ?, daily_baseline_time = ?, force_backup_every_days = ?,
                    retention_days = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    name,
                    ip,
                    api_port,
                    api_timeout_seconds,
                    username,
                    ftp_port,
                    1 if enabled else 0,
                    backup_check_interval_hours,
                    daily_baseline_time,
                    force_backup_every_days,
                    retention_days,
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


@app.post("/routers/{router_id}/toggle", dependencies=[Depends(require_basic_auth)])
def toggle_router(router_id: int):
    with get_db(settings.db_path) as conn:
        router = conn.execute("SELECT enabled FROM routers WHERE id = ?", (router_id,)).fetchone()
        if not router:
            raise HTTPException(status_code=404, detail="Router not found")
        new_value = 0 if router["enabled"] else 1
        conn.execute("UPDATE routers SET enabled = ?, updated_at = ? WHERE id = ?", (new_value, utcnow(), router_id))
    notice = "router_enabled" if new_value else "router_disabled"
    return RedirectResponse(f"/routers?notice={notice}", status_code=HTTP_303_SEE_OTHER)


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
            timeout=router.get("api_timeout_seconds") or 5,
            username=router["username"],
            password=router["encrypted_password"],
            ftp_port=router.get("ftp_port") or 21,
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


@app.post("/routers/{router_id}/test-telegram", dependencies=[Depends(require_basic_auth)])
def test_router_telegram(router_id: int):
    try:
        from app.services.telegram import get_default_recipients

        recipients = get_default_recipients()
        if not recipients:
            raise RuntimeError("No telegram recipients set in Settings")
        send_message(recipients, "RouterVault test message")
        return RedirectResponse(f"/routers/{router_id}?notice=telegram_ok", status_code=HTTP_303_SEE_OTHER)
    except Exception as exc:
        return RedirectResponse(
            f"/routers/{router_id}?error={quote_message(exc)}", status_code=HTTP_303_SEE_OTHER
        )


@app.post("/routers/{router_id}/backup", dependencies=[Depends(require_basic_auth)])
def trigger_backup(router_id: int):
    with get_db(settings.db_path) as conn:
        router = conn.execute(
            """
            SELECT *
            FROM routers
            WHERE id = ?
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
def update_settings(
    stale_backup_days: int = Form(3),
    telegram_token: str = Form(""),
    telegram_recipients: str = Form(""),
):
    with get_db(settings.db_path) as conn:
        conn.execute(
            "UPDATE settings SET stale_backup_days = ?, telegram_token = ?, telegram_recipients = ? WHERE id = 1",
            (
                stale_backup_days,
                telegram_token.strip(),
                telegram_recipients.strip(),
            ),
        )
    return RedirectResponse("/settings?notice=settings_saved", status_code=HTTP_303_SEE_OTHER)


@app.get("/health")
def health():
    return {"status": "ok"}
