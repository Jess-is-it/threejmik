import sqlite3
import json
import secrets
import time
import io
import zipfile
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from zoneinfo import ZoneInfo
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse
from starlette.status import HTTP_303_SEE_OTHER

from app.db import get_db, init_db, utcnow
from app.services.app_settings import load_app_settings
from app.services.backup import run_router_check
from app.services.config import settings
from app.services.mikrotik import MikroTikClient, check_port
from app.services.scheduler import scheduler, start_scheduler
from app.services.telegram import send_message

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="RouterVault")

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
settings.storage_path.mkdir(parents=True, exist_ok=True)

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
    username = (credentials.username or "").strip()
    password = credentials.password or ""
    if not username:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    try:
        with get_db(settings.db_path) as conn:
            row = conn.execute(
                "SELECT password, enabled FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    except sqlite3.OperationalError:
        # Older DBs may not have the users table yet (migration); initialize then retry once.
        init_db(settings.db_path)
        with get_db(settings.db_path) as conn:
            row = conn.execute(
                "SELECT password, enabled FROM users WHERE username = ?",
                (username,),
            ).fetchone()
    if not row or int(row["enabled"] or 0) != 1:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    if not secrets.compare_digest(password, row["password"] or ""):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    return username


def format_ts(value: Optional[str]) -> str:
    if not value:
        return "-"
    return value


def format_ts_ph(value: Optional[str]) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))
    dt_ph = dt.astimezone(ZoneInfo("Asia/Manila"))
    return dt_ph.strftime("%b %d, %Y %I:%M %p")


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


def with_query_params(url: str, params: dict) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update({k: str(v) for k, v in params.items() if v is not None and str(v) != ""})
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _config_backup_payload() -> dict:
    with get_db(settings.db_path) as conn:
        settings_row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        users = conn.execute("SELECT username, password, enabled, created_at, updated_at FROM users ORDER BY username ASC").fetchall()
        routers = conn.execute(
            """
            SELECT
              name, ip, api_port, api_timeout_seconds, username, encrypted_password, ftp_port,
              enabled, backup_check_interval_hours, daily_baseline_time, force_backup_every_days,
              retention_days, telegram_recipients,
              created_at, updated_at
            FROM routers
            ORDER BY created_at DESC
            """
        ).fetchall()

    return {
        "meta": {
            "app": "RouterVault",
            "format": 1,
            "created_at": utcnow(),
        },
        "settings": dict(settings_row) if settings_row else {},
        "routers": [dict(r) for r in routers],
        "users": [dict(u) for u in users],
    }


@app.get("/settings/config-backup/download", dependencies=[Depends(require_basic_auth)])
def download_config_backup():
    payload = _config_backup_payload()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("meta.json", json.dumps(payload.get("meta", {}), indent=2))
        zf.writestr("settings.json", json.dumps(payload.get("settings", {}), indent=2))
        zf.writestr("routers.json", json.dumps(payload.get("routers", []), indent=2))
        zf.writestr("users.json", json.dumps(payload.get("users", []), indent=2))
    buf.seek(0)
    filename = f"routervault_config_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(buf, media_type="application/zip", headers=headers)


@app.post("/settings/config-backup/restore", dependencies=[Depends(require_basic_auth)])
async def restore_config_backup(
    file: UploadFile = File(...),
    restore_settings: Optional[str] = Form(None),
    restore_routers: Optional[str] = Form(None),
    restore_users: Optional[str] = Form(None),
    confirm_word: str = Form(""),
):
    if (confirm_word or "").strip().lower() != "restore":
        return RedirectResponse("/settings?error=confirmation_required#rv-settings-general", status_code=HTTP_303_SEE_OTHER)

    data = await file.read()
    if not data:
        return RedirectResponse("/settings?error=invalid_file#rv-settings-general", status_code=HTTP_303_SEE_OTHER)
    if len(data) > 5 * 1024 * 1024:
        return RedirectResponse("/settings?error=file_too_large#rv-settings-general", status_code=HTTP_303_SEE_OTHER)

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return RedirectResponse("/settings?error=invalid_zip#rv-settings-general", status_code=HTTP_303_SEE_OTHER)

    def read_json(name: str, default):
        try:
            raw = zf.read(name)
        except Exception:
            return default
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return default

    meta = read_json("meta.json", {})
    if isinstance(meta, dict) and meta.get("app") and meta.get("app") != "RouterVault":
        return RedirectResponse("/settings?error=wrong_backup#rv-settings-general", status_code=HTTP_303_SEE_OTHER)

    settings_in = read_json("settings.json", {})
    routers_in = read_json("routers.json", [])
    users_in = read_json("users.json", [])

    now = utcnow()
    with get_db(settings.db_path) as conn:
        if restore_settings and isinstance(settings_in, dict):
            cols = [row[1] for row in conn.execute("PRAGMA table_info(settings)").fetchall()]
            values = {k: settings_in.get(k) for k in cols if k != "id" and k in settings_in}
            if values:
                assignments = ", ".join([f"{k} = ?" for k in values.keys()])
                conn.execute(f"UPDATE settings SET {assignments} WHERE id = 1", tuple(values.values()))

        if restore_users and isinstance(users_in, list):
            for u in users_in:
                if not isinstance(u, dict):
                    continue
                username = (u.get("username") or "").strip()
                password = u.get("password") or ""
                if not username or not password:
                    continue
                enabled = 1 if int(u.get("enabled") or 0) == 1 else 0
                row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                if row:
                    conn.execute(
                        "UPDATE users SET password = ?, enabled = ?, updated_at = ? WHERE username = ?",
                        (password, enabled, now, username),
                    )
                else:
                    created_at = u.get("created_at") or now
                    conn.execute(
                        "INSERT INTO users (username, password, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (username, password, enabled, created_at, now),
                    )

        if restore_routers and isinstance(routers_in, list):
            for r in routers_in:
                if not isinstance(r, dict):
                    continue
                name = (r.get("name") or "").strip()
                ip = (r.get("ip") or "").strip()
                if not name or not ip:
                    continue
                existing = conn.execute(
                    "SELECT id FROM routers WHERE name = ? ORDER BY id DESC LIMIT 1",
                    (name,),
                ).fetchone()
                router_fields = {
                    "ip": ip,
                    "api_port": int(r.get("api_port") or 8728),
                    "api_timeout_seconds": int(r.get("api_timeout_seconds") or 5),
                    "username": (r.get("username") or "").strip(),
                    "encrypted_password": (r.get("encrypted_password") or ""),
                    "ftp_port": int(r.get("ftp_port") or 21),
                    "enabled": 1 if int(r.get("enabled") or 0) == 1 else 0,
                    "backup_check_interval_hours": int(r.get("backup_check_interval_hours") or 6),
                    "daily_baseline_time": (r.get("daily_baseline_time") or "02:00"),
                    "force_backup_every_days": int(r.get("force_backup_every_days") or 7),
                    "retention_days": int(r.get("retention_days") or 30),
                    "telegram_recipients": (r.get("telegram_recipients") or ""),
                    "updated_at": now,
                }
                if existing:
                    assignments = ", ".join([f"{k} = ?" for k in router_fields.keys()])
                    conn.execute(
                        f"UPDATE routers SET {assignments} WHERE id = ?",
                        tuple(router_fields.values()) + (int(existing["id"]),),
                    )
                else:
                    created_at = r.get("created_at") or now
                    conn.execute(
                        """
                        INSERT INTO routers (
                          name, ip, api_port, api_timeout_seconds, username, encrypted_password, ftp_port, enabled,
                          backup_check_interval_hours, daily_baseline_time, force_backup_every_days, retention_days,
                          telegram_recipients, created_at, updated_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            name,
                            router_fields["ip"],
                            router_fields["api_port"],
                            router_fields["api_timeout_seconds"],
                            router_fields["username"],
                            router_fields["encrypted_password"],
                            router_fields["ftp_port"],
                            router_fields["enabled"],
                            router_fields["backup_check_interval_hours"],
                            router_fields["daily_baseline_time"],
                            router_fields["force_backup_every_days"],
                            router_fields["retention_days"],
                            router_fields["telegram_recipients"],
                            created_at,
                            now,
                        ),
                    )

    return RedirectResponse("/settings?notice=config_restored#rv-settings-general", status_code=HTTP_303_SEE_OTHER)


@app.get("/api/system/stats", dependencies=[Depends(require_basic_auth)])
def system_stats():
    data_path = settings.db_path.parent
    stats = {
        "cpu_percent": None,
        "mem_percent": None,
        "mem_used_gb": None,
        "mem_total_gb": None,
        "disk_percent": None,
        "disk_used_gb": None,
        "disk_total_gb": None,
        "uptime_seconds": None,
    }
    if psutil is None:
        return stats
    try:
        stats["cpu_percent"] = float(psutil.cpu_percent(interval=0.1))
        vm = psutil.virtual_memory()
        stats["mem_percent"] = float(vm.percent)
        stats["mem_used_gb"] = float(vm.used) / (1024**3)
        stats["mem_total_gb"] = float(vm.total) / (1024**3)
        du = psutil.disk_usage(str(data_path))
        stats["disk_percent"] = float(du.percent)
        stats["disk_used_gb"] = float(du.used) / (1024**3)
        stats["disk_total_gb"] = float(du.total) / (1024**3)
        stats["uptime_seconds"] = int(max(0.0, time.time() - float(psutil.boot_time())))
        return stats
    except Exception:
        return stats


@app.get("/download/{path:path}", dependencies=[Depends(require_basic_auth)])
def download_storage_file(path: str):
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise HTTPException(status_code=400, detail="Invalid path")
    base = settings.storage_path.resolve()
    full = (settings.storage_path / relative).resolve()
    if not full.is_relative_to(base):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not full.exists() or not full.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(full, filename=full.name, media_type="application/octet-stream")


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
        kpi_rows = conn.execute(
            """
            SELECT
                router_id,
                COUNT(1) AS total_backups,
                COALESCE(SUM(CASE WHEN trigger = 'auto' THEN 1 ELSE 0 END), 0) AS auto_backups,
                COALESCE(SUM(CASE WHEN trigger = 'auto' AND was_forced = 1 THEN 1 ELSE 0 END), 0) AS auto_forced_backups,
                COALESCE(SUM(CASE WHEN trigger = 'manual' THEN 1 ELSE 0 END), 0) AS manual_backups
            FROM backups
            GROUP BY router_id
            """
        ).fetchall()
        alert_counts = conn.execute(
            """
            SELECT
                COUNT(1) AS total,
                COALESCE(SUM(CASE WHEN viewed_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS viewed
            FROM alerts
            """
        ).fetchone()
        alerts_rows = conn.execute(
            """
            SELECT alerts.*, routers.name AS router_name
            FROM alerts
            LEFT JOIN routers ON routers.id = alerts.router_id
            ORDER BY alerts.created_at DESC
            LIMIT 100
            """
        ).fetchall()
        alerts_total = int(alert_counts["total"] or 0) if alert_counts else 0
        alerts_viewed = int(alert_counts["viewed"] or 0) if alert_counts else 0
    router_kpis = {
        int(row["router_id"]): {
            "total_backups": int(row["total_backups"] or 0),
            "auto_backups": int(row["auto_backups"] or 0),
            "auto_forced_backups": int(row["auto_forced_backups"] or 0),
            "manual_backups": int(row["manual_backups"] or 0),
        }
        for row in kpi_rows
    }

    def is_router_stale(router_row):
        days = int(router_row["force_backup_every_days"] or 7)
        return is_stale(router_row["last_success_at"], days)

    def is_router_connected(router_row):
        return not (router_row["last_error"] or "").strip()

    total_routers = len(routers)
    connected_routers = sum(1 for router in routers if is_router_connected(router))

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "routers": routers,
            "format_ts": format_ts,
            "format_ts_ph": format_ts_ph,
            "is_stale_router": is_router_stale,
            "parse_links": parse_links,
            "router_kpis": router_kpis,
            "total_routers": total_routers,
            "connected_routers": connected_routers,
            "is_connected_router": is_router_connected,
            "alerts": alerts_rows,
            "alerts_total": alerts_total,
            "alerts_viewed": alerts_viewed,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.get("/api/dashboard/poll", dependencies=[Depends(require_basic_auth)])
def dashboard_poll():
    with get_db(settings.db_path) as conn:
        routers = conn.execute(
            """
            SELECT id, last_error, last_backup_at, last_success_at, force_backup_every_days
            FROM routers
            ORDER BY created_at DESC
            """
        ).fetchall()
        settings_row = conn.execute("SELECT stale_backup_days FROM settings WHERE id = 1").fetchone()
        stale_days_default = int(settings_row["stale_backup_days"] or 3) if settings_row else 3
        alert_counts = conn.execute(
            """
            SELECT
                COUNT(1) AS total,
                COALESCE(SUM(CASE WHEN viewed_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS viewed
            FROM alerts
            """
        ).fetchone()
        recent_alerts = conn.execute(
            """
            SELECT alerts.*, routers.name AS router_name
            FROM alerts
            LEFT JOIN routers ON routers.id = alerts.router_id
            ORDER BY alerts.created_at DESC
            LIMIT 100
            """
        ).fetchall()

    total_routers = len(routers)
    routers_payload = []
    connected = 0
    for row in routers:
        last_error = (row["last_error"] or "").strip()
        is_connected = not last_error
        if is_connected:
            connected += 1
        days = int(row["force_backup_every_days"] or stale_days_default or 3)
        routers_payload.append(
            {
                "id": int(row["id"]),
                "connected": bool(is_connected),
                "last_error": last_error,
                "last_backup_at": row["last_backup_at"] or "",
                "last_backup_at_ph": format_ts_ph(row["last_backup_at"]),
                "last_success_at": row["last_success_at"] or "",
                "last_success_at_ph": format_ts_ph(row["last_success_at"]),
                "is_stale": bool(is_stale(row["last_success_at"], days)),
            }
        )

    alerts_total = int(alert_counts["total"] or 0) if alert_counts else 0
    alerts_viewed = int(alert_counts["viewed"] or 0) if alert_counts else 0
    recent_payload = []
    for alert in recent_alerts:
        recent_payload.append(
            {
                "id": int(alert["id"]),
                "created_at": alert["created_at"],
                "created_at_ph": format_ts_ph(alert["created_at"]),
                "router_name": alert["router_name"] or "",
                "level": (alert["level"] or "info").lower(),
                "title": alert["title"] or "",
                "message": alert["message"] or "",
                "viewed_at": alert["viewed_at"] or "",
                "is_new": not bool(alert["viewed_at"]),
            }
        )

    return {
        "total_routers": total_routers,
        "connected_routers": connected,
        "routers": routers_payload,
        "alerts_total": alerts_total,
        "alerts_viewed": alerts_viewed,
        "alerts_unread": max(0, alerts_total - alerts_viewed),
        "recent_alerts": recent_payload,
    }

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
        routers = conn.execute("SELECT * FROM routers ORDER BY name ASC").fetchall()
        backups = conn.execute(
            """
            SELECT backups.*, routers.name AS router_name, routers.ip, routers.api_port
            FROM backups
            JOIN routers ON routers.id = backups.router_id
            ORDER BY backups.created_at DESC
            """
        ).fetchall()
    selected_router_id = None
    try:
        selected_router_id = int(request.query_params.get("router_id", "") or 0) or None
    except ValueError:
        selected_router_id = None
    if selected_router_id is None and routers:
        selected_router_id = routers[0]["id"]
    parsed = []
    for backup in backups:
        logs_text = ""
        logs_preview = ""
        if backup["logs"]:
            try:
                entries = json.loads(backup["logs"])
                preview_lines = []
                for entry in entries[:2]:
                    preview_lines.append(
                        f"{entry.get('logged_at','')} {entry.get('topics','')} {entry.get('message','')}".strip()
                    )
                logs_preview = "\n".join([line for line in preview_lines if line])
                logs_text = "\n".join(
                    f"{entry.get('logged_at','')} {entry.get('topics','')} {entry.get('message','')}"
                    for entry in entries
                )
            except json.JSONDecodeError:
                logs_text = backup["logs"]
                logs_preview = "\n".join((backup["logs"] or "").splitlines()[:2])
        bdict = {**dict(backup)}
        bdict["important"] = int(bdict.get("important") or 0)
        parsed.append({**bdict, "logs_text": logs_text, "logs_preview": logs_preview})
    backups_by_router = {router["id"]: [] for router in routers}
    for backup in parsed:
        backups_by_router.setdefault(backup["router_id"], []).append(backup)

    router_stats = {}
    router_unread = {}
    for router in routers:
        router_dict = dict(router)
        latest_auto = None
        latest_auto_forced = None
        total_backups = len(backups_by_router.get(router["id"], []))
        for entry in backups_by_router.get(router["id"], []):
            if entry["trigger"] == "auto" and entry.get("was_forced"):
                latest_auto_forced = entry["created_at"]
            if entry["trigger"] == "auto" and not entry.get("was_forced"):
                latest_auto = entry["created_at"]
            if latest_auto and latest_auto_forced:
                break
        router_stats[router["id"]] = {
            "retention_days": router_dict.get("retention_days"),
            "check_interval_hours": router_dict.get("backup_check_interval_hours"),
            "daily_baseline_time": router_dict.get("daily_baseline_time"),
            "force_days": router_dict.get("force_backup_every_days"),
            "last_check_at": router_dict.get("last_check_at"),
            "last_auto_backup_at": latest_auto,
            "last_auto_forced_at": latest_auto_forced,
            "total_backups": total_backups,
        }
        last_seen = router_dict.get("last_backups_viewed_at") or router_dict.get("last_backup_at") or router_dict.get(
            "last_success_at"
        )
        unread = 0
        for entry in backups_by_router.get(router["id"], []):
            if not last_seen or entry["created_at"] > last_seen:
                unread += 1
        router_unread[router["id"]] = unread
    return templates.TemplateResponse(
        "backups.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "container_class": "container-fluid",
            "routers": routers,
            "selected_router_id": selected_router_id,
            "backups_by_router": backups_by_router,
            "all_backups": parsed,
            "router_stats": router_stats,
            "router_unread": router_unread,
            "format_ts_ph": format_ts_ph,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


def _link_to_path(link: str) -> Path:
    if not link:
        return Path()
    relative = ""
    if link.startswith("/storage/"):
        relative = link[len("/storage/") :]
    elif link.startswith("/download/"):
        relative = link[len("/download/") :]
    else:
        return Path()
    return settings.storage_path / relative


@app.post("/backups/{backup_id}/delete", dependencies=[Depends(require_basic_auth)])
def delete_backup(backup_id: int):
    with get_db(settings.db_path) as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")
        router_id = int(backup["router_id"])
        backup_path = _link_to_path(backup["backup_link"] or "")
        rsc_path = _link_to_path(backup["rsc_link"] or "")
        if backup_path.exists():
            backup_path.unlink()
        if rsc_path.exists():
            rsc_path.unlink()
        conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
        remaining = conn.execute(
            "SELECT COUNT(1) AS c FROM backups WHERE router_id = ?",
            (router_id,),
        ).fetchone()
        if remaining and int(remaining["c"] or 0) == 0:
            conn.execute(
                "UPDATE routers SET last_backup_log_at = NULL, updated_at = ? WHERE id = ?",
                (utcnow(), router_id),
            )
    return RedirectResponse(
        f"/backups?router_id={router_id}&notice=backup_deleted#tab-router-{router_id}",
        status_code=HTTP_303_SEE_OTHER,
    )


@app.post("/backups/{backup_id}/toggle-important", dependencies=[Depends(require_basic_auth)])
def toggle_backup_important(backup_id: int):
    with get_db(settings.db_path) as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")
        router_id = int(backup["router_id"])
        new_val = 0 if int(backup["important"] or 0) else 1
        conn.execute("UPDATE backups SET important = ? WHERE id = ?", (new_val, backup_id))
    return RedirectResponse(f"/backups?router_id={router_id}&notice=backup_updated", status_code=HTTP_303_SEE_OTHER)


@app.post("/routers/{router_id}/backups/viewed", dependencies=[Depends(require_basic_auth)])
def mark_backups_viewed(router_id: int):
    with get_db(settings.db_path) as conn:
        router = conn.execute("SELECT id FROM routers WHERE id = ?", (router_id,)).fetchone()
        if not router:
            raise HTTPException(status_code=404, detail="Router not found")
        conn.execute(
            "UPDATE routers SET last_backups_viewed_at = ?, updated_at = ? WHERE id = ?",
            (utcnow(), utcnow(), router_id),
        )
    return {"ok": True}


@app.post("/backups/{backup_id}/restore", dependencies=[Depends(require_basic_auth)])
def restore_backup(backup_id: int):
    with get_db(settings.db_path) as conn:
        backup = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")
        router = conn.execute("SELECT * FROM routers WHERE id = ?", (backup["router_id"],)).fetchone()
    if not router:
        raise HTTPException(status_code=404, detail="Router not found")
    router_id = int(router["id"])
    backup_path = _link_to_path(backup["backup_link"] or "")
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup file missing")
    try:
        with MikroTikClient(
            host=router["ip"],
            port=router["api_port"],
            timeout=router["api_timeout_seconds"] or 5,
            username=router["username"],
            password=router["encrypted_password"],
            ftp_port=router["ftp_port"] or 21,
        ) as client:
            client.restore_backup(backup_path.name, backup_path.read_bytes())
        try:
            from app.services.alerts import create_alert

            create_alert(
                router_id=int(router["id"]),
                level="warning",
                kind="restore",
                title=f"Restore started: {router['name']}",
                message=f"Restore initiated for {backup_path.name}.",
                meta={"backup_id": int(backup_id)},
                dedupe_seconds=30,
            )
        except Exception:
            pass
        return RedirectResponse(
            f"/backups?router_id={router_id}&notice=restore_started#tab-router-{router_id}",
            status_code=HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        try:
            from app.services.alerts import create_alert

            create_alert(
                router_id=int(router["id"]),
                level="error",
                kind="restore",
                title=f"Restore failed: {router['name']}",
                message=str(exc),
                meta={"backup_id": int(backup_id)},
                dedupe_seconds=60,
            )
        except Exception:
            pass
        return RedirectResponse(
            f"/backups?router_id={router_id}&error={quote_message(exc)}#tab-router-{router_id}",
            status_code=HTTP_303_SEE_OTHER,
        )


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


@app.post("/routers/bulk", dependencies=[Depends(require_basic_auth)])
async def create_router_bulk(request: Request):
    form = await request.form()
    indices = sorted(
        {
            int(key.split("_")[-1])
            for key in form.keys()
            if key.startswith("name_") and key.split("_")[-1].isdigit()
        }
    )

    def parse_int(value: str, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    rows = []
    for idx in indices:
        name = (form.get(f"name_{idx}") or "").strip()
        ip = (form.get(f"ip_{idx}") or "").strip()
        username = (form.get(f"username_{idx}") or "").strip()
        password = (form.get(f"password_{idx}") or "").strip()
        api_port = parse_int(form.get(f"api_port_{idx}") or "", 8728)
        api_timeout_seconds = parse_int(form.get(f"api_timeout_seconds_{idx}") or "", 5)
        ftp_port = parse_int(form.get(f"ftp_port_{idx}") or "", 21)
        if not any([name, ip, username, password]):
            continue
        missing = []
        if not name:
            missing.append("name")
        if not ip:
            missing.append("ip")
        if not username:
            missing.append("username")
        if not password:
            missing.append("password")
        if missing:
            return RedirectResponse(
                f"/routers?error=Row%20{idx + 1}%20missing%20{',%20'.join(missing)}",
                status_code=HTTP_303_SEE_OTHER,
            )
        rows.append(
            (
                name,
                ip,
                api_port,
                api_timeout_seconds,
                username,
                password,
                ftp_port,
                1,
                6,
                "02:00",
                7,
                30,
            )
        )

    if not rows:
        return RedirectResponse("/routers?error=No%20router%20data%20found", status_code=HTTP_303_SEE_OTHER)

    now = utcnow()
    with get_db(settings.db_path) as conn:
        conn.executemany(
            """
            INSERT INTO routers
            (name, ip, api_port, api_timeout_seconds, username, encrypted_password, ftp_port, enabled,
             backup_check_interval_hours, daily_baseline_time, force_backup_every_days,
             retention_days, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [row + (now, now) for row in rows],
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
        with MikroTikClient(
            host=ip,
            port=api_port,
            timeout=api_timeout_seconds or 5,
            username=username,
            password=password,
            ftp_port=ftp_port or 21,
        ) as client:
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


@app.post("/routers/test-draft-ajax", dependencies=[Depends(require_basic_auth)])
def test_router_draft_ajax(
    ip: str = Form(...),
    api_port: int = Form(8728),
    api_timeout_seconds: int = Form(5),
    username: str = Form(...),
    password: str = Form(...),
    ftp_port: int = Form(21),
):
    try:
        with MikroTikClient(
            host=ip,
            port=api_port,
            timeout=api_timeout_seconds or 5,
            username=username,
            password=password,
            ftp_port=ftp_port or 21,
        ) as client:
            ok, message = client.test_connection()
        if not ok:
            ok, message = check_port(ip, api_port)
        return {"ok": bool(ok), "message": message or ""}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


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
        prior_error = (router["last_error"] or "").strip()
        with MikroTikClient(
            host=router["ip"],
            port=router["api_port"],
            timeout=router["api_timeout_seconds"] or 5,
            username=router["username"],
            password=router["encrypted_password"],
            ftp_port=router["ftp_port"] or 21,
        ) as client:
            ok, message = client.test_connection()
        last_error = None
        if not ok:
            tcp_ok, tcp_message = check_port(router["ip"], router["api_port"])
            tcp_summary = "TCP ok" if tcp_ok else "TCP failed"
            message = f"{message} ({tcp_summary}: {tcp_message})" if message else f"{tcp_summary}: {tcp_message}"
            last_error = message
        with get_db(settings.db_path) as conn:
            conn.execute(
                "UPDATE routers SET last_error = ?, updated_at = ? WHERE id = ?",
                (last_error, utcnow(), router_id),
            )
        try:
            from app.services.alerts import create_alert

            if ok and prior_error:
                create_alert(
                    router_id=int(router_id),
                    level="info",
                    kind="router_recovered",
                    title=f"Router recovered: {router['name']}",
                    message=f"RouterOS API checks are passing again for {router['name']}.",
                    dedupe_seconds=3600,
                )
            if not ok:
                create_alert(
                    router_id=int(router_id),
                    level="error",
                    kind="backup_failed",
                    title=f"Router API check failed: {router['name']}",
                    message=message or "RouterOS API check failed",
                    meta={"ip": router["ip"], "api_port": int(router["api_port"] or 8728)},
                    dedupe_seconds=900,
                )
        except Exception:
            pass
        return RedirectResponse(
            f"/routers/{router_id}?notice={'router_ok' if ok else 'router_fail'}&error={'' if ok else quote_message(message)}",
            status_code=HTTP_303_SEE_OTHER,
        )
    except Exception as exc:
        return RedirectResponse(
            f"/routers/{router_id}?notice=router_fail&error={quote_message(exc)}",
            status_code=HTTP_303_SEE_OTHER,
        )


@app.post("/routers/{router_id}/test-ajax", dependencies=[Depends(require_basic_auth)])
def test_router_ajax(router_id: int):
    with get_db(settings.db_path) as conn:
        router = conn.execute("SELECT * FROM routers WHERE id = ?", (router_id,)).fetchone()
    if not router:
        return {"ok": False, "message": "Router not found"}
    try:
        prior_error = (router["last_error"] or "").strip()
        with MikroTikClient(
            host=router["ip"],
            port=router["api_port"],
            timeout=router["api_timeout_seconds"] or 5,
            username=router["username"],
            password=router["encrypted_password"],
            ftp_port=router["ftp_port"] or 21,
        ) as client:
            ok, message = client.test_connection()
        last_error = None
        if not ok:
            tcp_ok, tcp_message = check_port(router["ip"], router["api_port"])
            tcp_summary = "TCP ok" if tcp_ok else "TCP failed"
            message = f"{message} ({tcp_summary}: {tcp_message})" if message else f"{tcp_summary}: {tcp_message}"
            last_error = message
        with get_db(settings.db_path) as conn:
            conn.execute(
                "UPDATE routers SET last_error = ?, updated_at = ? WHERE id = ?",
                (last_error, utcnow(), router_id),
            )
        try:
            from app.services.alerts import create_alert

            if ok and prior_error:
                create_alert(
                    router_id=int(router_id),
                    level="info",
                    kind="router_recovered",
                    title=f"Router recovered: {router['name']}",
                    message=f"RouterOS API checks are passing again for {router['name']}.",
                    dedupe_seconds=3600,
                )
            if not ok:
                create_alert(
                    router_id=int(router_id),
                    level="error",
                    kind="backup_failed",
                    title=f"Router API check failed: {router['name']}",
                    message=message or "RouterOS API check failed",
                    meta={"ip": router["ip"], "api_port": int(router["api_port"] or 8728)},
                    dedupe_seconds=900,
                )
        except Exception:
            pass
        return {"ok": bool(ok), "message": message or ""}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


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
def trigger_backup(request: Request, router_id: int):
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
    next_url = request.query_params.get("next") or f"/routers/{router_id}"
    try:
        run_router_check(dict(router), baseline_due=False, force=True, trigger="manual")
        return RedirectResponse(with_query_params(next_url, {"notice": "backup_forced"}), status_code=HTTP_303_SEE_OTHER)
    except Exception as exc:
        try:
            from app.services.alerts import create_alert

            create_alert(
                router_id=int(router_id),
                level="error",
                kind="backup_failed",
                title=f"Manual backup failed: {router['name']}",
                message=str(exc),
                dedupe_seconds=60,
            )
        except Exception:
            pass
        return RedirectResponse(
            with_query_params(next_url, {"error": str(exc)}), status_code=HTTP_303_SEE_OTHER
        )


@app.get("/settings", dependencies=[Depends(require_basic_auth)], response_class=HTMLResponse)
def settings_page(request: Request):
    with get_db(settings.db_path) as conn:
        settings_row = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        users = conn.execute("SELECT * FROM users ORDER BY username ASC").fetchall()
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "app_name": "RouterVault",
            "settings": settings_row,
            "users": users,
            "format_ts_ph": format_ts_ph,
            "notice": request.query_params.get("notice"),
            "error": request.query_params.get("error"),
        },
    )


@app.post("/settings", dependencies=[Depends(require_basic_auth)])
def update_settings(
    section: str = Form("all"),
    telegram_token: Optional[str] = Form(None),
    telegram_recipients: Optional[str] = Form(None),
    mock_mode: Optional[str] = Form(None),
    export_show_sensitive: Optional[str] = Form(None),
    alerts_retention_days: Optional[str] = Form(None),
    telegram_notify_backup_created: Optional[str] = Form(None),
    telegram_notify_backup_failed: Optional[str] = Form(None),
    telegram_notify_router_recovered: Optional[str] = Form(None),
    telegram_notify_manual_backup: Optional[str] = Form(None),
    telegram_notify_restore: Optional[str] = Form(None),
):
    section_key = (section or "").strip().lower() or "all"
    with get_db(settings.db_path) as conn:
        current = conn.execute("SELECT * FROM settings WHERE id = 1").fetchone()
        current_dict = dict(current) if current else {}

        update_general = section_key in ("all", "general")
        update_telegram = section_key in ("all", "telegram")

        def flag(value: Optional[str], default: int, should_update: bool) -> int:
            if not should_update:
                return int(default)
            return 1 if value is not None else 0

        if update_telegram:
            new_token = (telegram_token or "").strip()
            new_recipients = (telegram_recipients or "").strip()
        else:
            new_token = current_dict.get("telegram_token") or ""
            new_recipients = current_dict.get("telegram_recipients") or ""

        new_mock = flag(mock_mode, int(current_dict.get("mock_mode") or 0), update_general)
        new_sensitive = flag(export_show_sensitive, int(current_dict.get("export_show_sensitive") or 0), update_general)

        if not update_general:
            retention_days = int(current_dict.get("alerts_retention_days") or 30)
        else:
            try:
                retention_days = max(1, int((alerts_retention_days or "").strip() or 30))
            except Exception:
                retention_days = int(current_dict.get("alerts_retention_days") or 30) or 30

        notify_backup_created = flag(
            telegram_notify_backup_created, int(current_dict.get("telegram_notify_backup_created") or 0), update_telegram
        )
        notify_backup_failed = flag(
            telegram_notify_backup_failed, int(current_dict.get("telegram_notify_backup_failed") or 1), update_telegram
        )
        notify_router_recovered = flag(
            telegram_notify_router_recovered,
            int(current_dict.get("telegram_notify_router_recovered") or 1),
            update_telegram,
        )
        notify_manual_backup = flag(
            telegram_notify_manual_backup, int(current_dict.get("telegram_notify_manual_backup") or 0), update_telegram
        )
        notify_restore = flag(telegram_notify_restore, int(current_dict.get("telegram_notify_restore") or 1), update_telegram)

        conn.execute(
            """
            UPDATE settings
            SET telegram_token = ?,
                telegram_recipients = ?,
                mock_mode = ?,
                export_show_sensitive = ?,
                alerts_retention_days = ?,
                telegram_notify_backup_created = ?,
                telegram_notify_backup_failed = ?,
                telegram_notify_router_recovered = ?,
                telegram_notify_manual_backup = ?,
                telegram_notify_restore = ?
            WHERE id = 1
            """,
            (
                new_token,
                new_recipients,
                new_mock,
                new_sensitive,
                retention_days,
                notify_backup_created,
                notify_backup_failed,
                notify_router_recovered,
                notify_manual_backup,
                notify_restore,
            ),
    )
    tab_anchor = "rv-settings-general"
    if section_key == "telegram":
        tab_anchor = "rv-settings-telegram"
    return RedirectResponse(f"/settings?notice=settings_saved#{tab_anchor}", status_code=HTTP_303_SEE_OTHER)


@app.post("/settings/users", dependencies=[Depends(require_basic_auth)])
def add_user(username: str = Form(""), password: str = Form("")):
    username = (username or "").strip()
    password = password or ""
    if not username or not password:
        return RedirectResponse("/settings?error=user_required#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
    now = utcnow()
    try:
        with get_db(settings.db_path) as conn:
            conn.execute(
                "INSERT INTO users (username, password, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
                (username, password, now, now),
            )
        return RedirectResponse("/settings?notice=user_added#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
    except sqlite3.IntegrityError:
        return RedirectResponse("/settings?error=user_exists#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)


@app.post("/settings/users/save", dependencies=[Depends(require_basic_auth)])
def save_user(user_id: Optional[str] = Form(None), username: str = Form(""), password: str = Form("")):
    username = (username or "").strip()
    password = password or ""
    if not username:
        return RedirectResponse("/settings?error=user_required#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
    now = utcnow()
    try:
        uid = int(user_id) if user_id is not None and str(user_id).strip() != "" else None
    except Exception:
        uid = None

    with get_db(settings.db_path) as conn:
        if uid is None:
            if not password:
                return RedirectResponse("/settings?error=password_required#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
            try:
                conn.execute(
                    "INSERT INTO users (username, password, enabled, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
                    (username, password, now, now),
                )
                return RedirectResponse("/settings?notice=user_added#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
            except sqlite3.IntegrityError:
                return RedirectResponse("/settings?error=user_exists#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)

        current = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not current:
            return RedirectResponse("/settings?error=user_not_found#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
        # Update username (unique) and optionally password (blank means keep).
        try:
            if password:
                conn.execute(
                    "UPDATE users SET username = ?, password = ?, updated_at = ? WHERE id = ?",
                    (username, password, now, uid),
                )
            else:
                conn.execute(
                    "UPDATE users SET username = ?, updated_at = ? WHERE id = ?",
                    (username, now, uid),
                )
            return RedirectResponse("/settings?notice=user_updated#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
        except sqlite3.IntegrityError:
            return RedirectResponse("/settings?error=user_exists#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)


@app.post("/settings/users/{user_id}/password", dependencies=[Depends(require_basic_auth)])
def set_user_password(user_id: int, password: str = Form("")):
    password = password or ""
    if not password:
        return RedirectResponse("/settings?error=password_required#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
    now = utcnow()
    with get_db(settings.db_path) as conn:
        user = conn.execute("SELECT id FROM users WHERE id = ?", (int(user_id),)).fetchone()
        if not user:
            return RedirectResponse("/settings?error=user_not_found#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
        conn.execute("UPDATE users SET password = ?, updated_at = ? WHERE id = ?", (password, now, int(user_id)))
    return RedirectResponse("/settings?notice=password_updated#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)


@app.post("/settings/users/{user_id}/delete")
def delete_user(user_id: int, current_user: str = Depends(require_basic_auth)):
    with get_db(settings.db_path) as conn:
        target = conn.execute("SELECT id, username, protected FROM users WHERE id = ?", (int(user_id),)).fetchone()
        if not target:
            return RedirectResponse("/settings?error=user_not_found#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
        if int(target["protected"] or 0) == 1:
            return RedirectResponse(
                "/settings?error=cannot_delete_protected_user#rv-settings-auth",
                status_code=HTTP_303_SEE_OTHER,
            )
        if (target["username"] or "") == (current_user or ""):
            return RedirectResponse("/settings?error=cannot_delete_current_user#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
        count = conn.execute("SELECT COUNT(1) AS c FROM users WHERE enabled = 1").fetchone()
        enabled_count = int(count["c"] or 0) if count else 0
        if enabled_count <= 1:
            return RedirectResponse("/settings?error=cannot_delete_last_user#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)
        conn.execute("DELETE FROM users WHERE id = ?", (int(user_id),))
    return RedirectResponse("/settings?notice=user_deleted#rv-settings-auth", status_code=HTTP_303_SEE_OTHER)


@app.post("/settings/format-backups", dependencies=[Depends(require_basic_auth)])
def format_backups(confirm_word: str = Form(""), include_routers: Optional[str] = Form(None)):
    if (confirm_word or "").strip().lower() != "format":
        return RedirectResponse("/settings?error=confirmation_required", status_code=HTTP_303_SEE_OTHER)
    # Delete DB records
    with get_db(settings.db_path) as conn:
        conn.execute("DELETE FROM backups")
        conn.execute("DELETE FROM router_logs")
        conn.execute("DELETE FROM alerts")
        if include_routers:
            conn.execute("DELETE FROM routers")
        else:
            conn.execute(
                """
                UPDATE routers
                SET last_backup_log_at = NULL,
                    last_backup_at = NULL,
                    last_success_at = NULL,
                    last_log_check_at = NULL,
                    last_backup_links = NULL,
                    last_hash = NULL,
                    last_config_change_at = NULL,
                    last_backup_links = NULL,
                    last_check_at = NULL,
                    last_baseline_at = NULL,
                    updated_at = ?
                """,
                (utcnow(),),
            )
    # Delete stored backup/rsc files on disk
    try:
        base = settings.storage_path
        if base.exists():
            for router_dir in base.iterdir():
                if not router_dir.is_dir():
                    continue
                for sub in ("backups", "rsc"):
                    folder = router_dir / sub
                    if folder.exists():
                        for entry in folder.iterdir():
                            if entry.is_file():
                                entry.unlink(missing_ok=True)
    except Exception:
        # ignore filesystem errors, DB already cleared
        pass
    return RedirectResponse("/settings?notice=backups_formatted", status_code=HTTP_303_SEE_OTHER)


@app.post("/alerts/viewed", dependencies=[Depends(require_basic_auth)])
def mark_alerts_viewed():
    from app.services.alerts import mark_all_alerts_viewed

    viewed, total = mark_all_alerts_viewed()
    return {"ok": True, "viewed": viewed, "total": total}


@app.post("/alerts/clear", dependencies=[Depends(require_basic_auth)])
def clear_alerts():
    from app.services.alerts import clear_all_alerts

    _deleted, viewed, total = clear_all_alerts()
    return {"ok": True, "viewed": viewed, "total": total}


@app.get("/health")
def health():
    return {"status": "ok"}
