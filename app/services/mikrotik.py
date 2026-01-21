import hashlib
import io
import socket
from ftplib import FTP
from datetime import datetime
from typing import Dict, List, Tuple

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

    def test_connection(self) -> Tuple[bool, str]:
        if settings.mock_mode:
            return True, "Mocked connection"
        try:
            api = self._connect()
            list(api("/system/resource/print"))
            return True, "Connected"
        except Exception as exc:
            return False, str(exc)

    def fetch_logs(self, since: str | None) -> List[Dict[str, str]]:
        if settings.mock_mode:
            return []
        api = self._connect()
        logs = list(api("/log/print"))
        filtered = []
        since_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since)
            except ValueError:
                since_dt = None
        for entry in logs:
            logged_at = entry.get("time") or ""
            message = entry.get("message") or ""
            topics = entry.get("topics") or ""
            filtered.append({"logged_at": logged_at, "message": message, "topics": topics})
        if since_dt:
            return filtered
        return filtered

    def export_config(self) -> str:
        if settings.mock_mode:
            seed = datetime.utcnow().isoformat()
            return f"# mock export {seed}\n/interface print\n"
        api = self._connect()
        try:
            export_lines = api("/export")
            return "\n".join([line.get("text", "") for line in export_lines])
        except Exception as exc:
            raise RuntimeError(f"Failed to export config: {exc}")

    def create_backup(self, name: str) -> bytes:
        if settings.mock_mode:
            return f"backup::{name}".encode("utf-8")
        api = self._connect()
        api("/system/backup/save", name=name)
        return self._download_file(f"{name}.backup")

    def create_rsc_file(self, name: str) -> bytes:
        if settings.mock_mode:
            return self.export_config().encode("utf-8")
        api = self._connect()
        api("/export", file=name)
        return self._download_file(f"{name}.rsc")

    def _download_file(self, filename: str) -> bytes:
        with FTP() as ftp:
            ftp.connect(self.host, self.ftp_port, timeout=10)
            ftp.login(self.username, self.password)
            buffer = io.BytesIO()
            ftp.retrbinary(f"RETR {filename}", buffer.write)
            try:
                ftp.delete(filename)
            except Exception:
                pass
            return buffer.getvalue()

    def restore_backup(self, backup_name: str, content: bytes) -> None:
        if settings.mock_mode:
            return
        with FTP() as ftp:
            ftp.connect(self.host, self.ftp_port, timeout=10)
            ftp.login(self.username, self.password)
            ftp.storbinary(f"STOR {backup_name}", io.BytesIO(content))
        api = self._connect()
        base_name = backup_name[:-7] if backup_name.endswith(".backup") else backup_name
        api("/system/backup/load", name=base_name)


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
