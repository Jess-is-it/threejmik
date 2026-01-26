import hashlib
import io
import socket
import time
import re
from ftplib import FTP, error_perm
from datetime import date, datetime, time as dtime
from typing import Dict, List, Tuple

from app.services.app_settings import export_show_sensitive, is_mock_mode
from app.services.config import settings

try:
    from librouteros import connect
except ImportError:  # pragma: no cover
    connect = None


class MikroTikClient:
    def __init__(self, host: str, port: int, username: str, password: str, timeout: int = 5, ftp_port: int = 21):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ftp_port = ftp_port
        self._api = None

    def _connect(self):
        if connect is None:
            raise RuntimeError("librouteros is not installed")
        try:
            return connect(
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                timeout=self.timeout,
            )
        except TypeError:
            return connect(
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
            )

    def _get_api(self):
        api = self._api
        if api is not None:
            return api
        api = self._connect()
        self._api = api
        return api

    def close(self) -> None:
        api = self._api
        self._api = None
        if api is None:
            return
        for attr in ("close", "disconnect"):
            fn = getattr(api, attr, None)
            if callable(fn):
                try:
                    fn()
                    return
                except Exception:
                    pass
        transport = getattr(api, "transport", None)
        if transport is not None:
            fn = getattr(transport, "close", None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def test_connection(self) -> Tuple[bool, str]:
        if is_mock_mode():
            return True, ""
        try:
            api = self._get_api()
            list(api("/system/resource/print"))
            return True, "Connected"
        except Exception as exc:
            return False, str(exc)

    def get_router_clock_iso(self) -> str:
        dt = self._get_router_clock()
        if dt is None:
            return datetime.utcnow().replace(microsecond=0).isoformat(sep=" ")
        return dt.replace(microsecond=0).isoformat(sep=" ")

    def _get_router_clock(self) -> datetime | None:
        if is_mock_mode():
            return datetime.utcnow()
        try:
            api = self._get_api()
            row = list(api("/system/clock/print"))[0]
            date_raw = (row.get("date") or "").strip()
            time_raw = (row.get("time") or "").strip()
            if not date_raw or not time_raw:
                return None
            parsed_date: date | None = None
            for fmt in ("%b/%d/%Y", "%Y-%m-%d", "%Y/%m/%d"):
                try:
                    parsed_date = datetime.strptime(date_raw, fmt).date()
                    break
                except ValueError:
                    continue
            if parsed_date is None:
                return None
            try:
                parsed_time: dtime = datetime.strptime(time_raw, "%H:%M:%S").time()
            except ValueError:
                return None
            return datetime.combine(parsed_date, parsed_time)
        except Exception:
            return None

    def _parse_log_datetime(self, entry: Dict[str, str], router_now: datetime | None) -> datetime | None:
        date_raw = (entry.get("date") or "").strip()
        time_raw = (entry.get("time") or "").strip()
        if date_raw and time_raw:
            for d_fmt in ("%b/%d/%Y", "%Y-%m-%d", "%Y/%m/%d", "%b/%d/%y"):
                try:
                    parsed_date = datetime.strptime(date_raw, d_fmt).date()
                    parsed_time = datetime.strptime(time_raw, "%H:%M:%S").time()
                    return datetime.combine(parsed_date, parsed_time)
                except ValueError:
                    continue

        # Some RouterOS variants include date inside `time`, e.g. "jan/22 19:08:09".
        if time_raw and " " in time_raw and "/" in time_raw:
            for fmt in ("%b/%d %H:%M:%S", "%b/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(time_raw, fmt)
                    if dt.year == 1900 and router_now is not None:
                        dt = dt.replace(year=router_now.year)
                    return dt
                except ValueError:
                    continue

        # If the log line only contains a time-of-day, assume router "today".
        if time_raw and router_now is not None:
            try:
                parsed_time = datetime.strptime(time_raw, "%H:%M:%S").time()
                return datetime.combine(router_now.date(), parsed_time)
            except ValueError:
                return None
        return None

    def fetch_logs(self, since: str | None) -> List[Dict[str, str]]:
        if is_mock_mode():
            return []
        api = self._get_api()
        logs = list(api("/log/print"))
        filtered: List[Dict[str, str]] = []

        since_dt: datetime | None = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                since_dt = None
        router_now = self._get_router_clock()

        noise_phrases = (
            "logged in",
            "logged out",
            "login failure",
            "disconnect",
            "disconnected",
            "connecting",
            "connected",
            "terminating",
            "terminated",
            "initializing",
            "initialized",
            "session closed",
            "link down",
            "link up",
        )

        config_change_re = re.compile(
            r"\b(config(?:uration)?\s+changed|changed|added|removed|created|deleted|modified|set|enabled|disabled|imported|exported)\b.*\bby\b",
            re.IGNORECASE,
        )

        for entry in logs:
            logged_dt = self._parse_log_datetime(entry, router_now)
            if since_dt is not None and logged_dt is not None and logged_dt < since_dt:
                continue

            logged_at = logged_dt.isoformat(sep=" ") if logged_dt is not None else (entry.get("time") or "")
            message = entry.get("message") or ""
            topics = entry.get("topics") or ""
            message_l = message.lower()
            topics_l = topics.lower()

            # Exclude common noisy session/device state logs.
            if any(phrase in message_l for phrase in noise_phrases):
                continue

            # Keep only logs likely to represent configuration changes.
            # We treat scripts/scheduler as potentially-config-changing events.
            if "script" in topics_l or "scheduler" in topics_l:
                keep = True
            else:
                keep = bool(config_change_re.search(message))
            if not keep:
                continue

            filtered.append({"logged_at": logged_at, "message": message, "topics": topics})
        return filtered

    def export_config(self) -> str:
        if is_mock_mode():
            seed = datetime.utcnow().isoformat()
            return f"# mock export {seed}\n/interface print\n"
        api = self._get_api()
        try:
            try:
                if export_show_sensitive():
                    export_lines = api("/export", **{"show-sensitive": "yes"})
                else:
                    export_lines = api("/export")
            except Exception:
                export_lines = api("/export")

            rendered: list[str] = []
            for line in export_lines:
                if isinstance(line, str):
                    rendered.append(line)
                    continue
                if not isinstance(line, dict):
                    continue
                for key in ("text", "ret", "message", "data"):
                    value = line.get(key)
                    if isinstance(value, str) and value:
                        rendered.append(value)
                        break
            return "\n".join(rendered)
        except Exception as exc:
            raise RuntimeError(f"Failed to export config: {exc}")

    def create_backup(self, name: str) -> bytes:
        if is_mock_mode():
            return f"backup::{name}".encode("utf-8")
        api = self._get_api()
        list(api("/system/backup/save", name=name))
        filename = self._wait_for_file(f"{name}.backup")
        return self._download_file(filename)

    def create_rsc_file(self, name: str) -> bytes:
        if is_mock_mode():
            return self.export_config().encode("utf-8")
        api = self._get_api()
        try:
            if export_show_sensitive():
                list(api("/export", file=name, **{"show-sensitive": "yes"}))
            else:
                list(api("/export", file=name))
        except Exception:
            list(api("/export", file=name))
        filename = self._wait_for_file(f"{name}.rsc")
        return self._download_file(filename)

    def _find_file_path(self, filename: str) -> str | None:
        try:
            api = self._get_api()
            files = list(api("/file/print"))
            for entry in files:
                name = entry.get("name") or ""
                if name == filename or name.endswith("/" + filename):
                    return name
        except Exception:
            return None
        return None

    def _remove_file_via_api(self, filename: str) -> None:
        try:
            api = self._get_api()
            files = list(api("/file/print"))
            for entry in files:
                name = entry.get("name") or ""
                if name == filename or name.endswith("/" + filename):
                    file_id = entry.get(".id")
                    if file_id:
                        list(api("/file/remove", numbers=file_id))
                        return
        except Exception:
            return

    def _wait_for_file(self, filename: str, timeout_seconds: float = 20.0) -> str:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            found = self._find_file_path(filename)
            if found:
                return found
            time.sleep(0.5)
        return filename

    def _download_file(self, filename: str) -> bytes:
        with FTP() as ftp:
            ftp.connect(self.host, self.ftp_port, timeout=10)
            ftp.login(self.username, self.password)
            buffer = io.BytesIO()
            for attempt in range(0, 6):
                try:
                    ftp.retrbinary(f"RETR {filename}", buffer.write)
                    break
                except error_perm as exc:
                    if "550" in str(exc) and attempt < 5:
                        time.sleep(0.5 + attempt * 0.5)
                        continue
                    raise
            try:
                ftp.delete(filename)
            except Exception:
                self._remove_file_via_api(filename)
            return buffer.getvalue()

    def restore_backup(self, backup_name: str, content: bytes) -> None:
        if is_mock_mode():
            return
        with FTP() as ftp:
            ftp.connect(self.host, self.ftp_port, timeout=10)
            ftp.login(self.username, self.password)
            ftp.storbinary(f"STOR {backup_name}", io.BytesIO(content))
        api = self._get_api()
        base_name = backup_name[:-7] if backup_name.endswith(".backup") else backup_name
        list(api("/system/backup/load", name=base_name))


def normalize_export(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return "\n".join(lines)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_port(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "TCP connect ok"
    except Exception as exc:
        return False, str(exc)
