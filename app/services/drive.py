from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from typing import Iterable, Tuple

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

from app.services.config import settings

DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]
ROOT_FOLDER_NAME = "RouterVault"


def get_drive_service():
    if not settings.google_credentials:
        raise RuntimeError("Missing ROUTERVAULT_GOOGLE_CREDENTIALS")
    creds = service_account.Credentials.from_service_account_file(
        settings.google_credentials, scopes=DRIVE_SCOPES
    )
    return build("drive", "v3", credentials=creds)


def ensure_folder(service, name: str, parent_id: str | None) -> Tuple[str, str]:
    query = f"mimeType = 'application/vnd.google-apps.folder' and name = '{name}'"
    if parent_id:
        query += f" and '{parent_id}' in parents"
    response = service.files().list(q=query, fields="files(id, name, webViewLink)").execute()
    files = response.get("files", [])
    if files:
        file = files[0]
        return file["id"], file.get("webViewLink", "")
    metadata = {
        "name": name,
        "mimeType": "application/vnd.google-apps.folder",
    }
    if parent_id:
        metadata["parents"] = [parent_id]
    folder = service.files().create(body=metadata, fields="id, webViewLink").execute()
    return folder["id"], folder.get("webViewLink", "")


def ensure_branch_folders(service, branch_name: str) -> Tuple[str, str, str, str]:
    root_id, root_link = ensure_folder(service, ROOT_FOLDER_NAME, None)
    branch_id, branch_link = ensure_folder(service, branch_name, root_id)
    backups_id, _ = ensure_folder(service, "backups", branch_id)
    rsc_id, _ = ensure_folder(service, "rsc", branch_id)
    return branch_id, branch_link, backups_id, rsc_id


def upload_file(
    service,
    file_name: str,
    content: bytes,
    parent_id: str,
    mime_type: str = "application/octet-stream",
    app_props: dict | None = None,
) -> str:
    media = MediaIoBaseUpload(io.BytesIO(content), mimetype=mime_type)
    body = {
        "name": file_name,
        "parents": [parent_id],
    }
    if app_props:
        body["appProperties"] = app_props
    uploaded = (
        service.files()
        .create(body=body, media_body=media, fields="id, webViewLink")
        .execute()
    )
    return uploaded.get("webViewLink", "")


def grant_branch_access(service, folder_id: str, emails: Iterable[str]) -> None:
    for email in emails:
        if not email:
            continue
        permission = {
            "type": "user",
            "role": "reader",
            "emailAddress": email,
        }
        service.permissions().create(fileId=folder_id, body=permission).execute()


def delete_old_files(service, folder_id: str, retention_days: int) -> int:
    query = (
        "'{}' in parents and appProperties has {{ key='routervault' and value='true' }}"
    ).format(folder_id)
    response = service.files().list(q=query, fields="files(id, name, createdTime)").execute()
    files = response.get("files", [])
    deleted = 0
    if not files:
        return deleted
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    for file in files:
        created = file.get("createdTime")
        if not created:
            continue
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            continue
        if created_dt <= cutoff:
            service.files().delete(fileId=file["id"]).execute()
            deleted += 1
    return deleted
