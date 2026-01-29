#!/usr/bin/env bash
set -euo pipefail

REPO_URL_DEFAULT="https://github.com/Jess-is-it/threejmik.git"
REPO_REF_DEFAULT="master"
INSTALL_DIR_DEFAULT="/opt/routervault"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  fi
  echo "This installer must run as root (or with sudo)." >&2
  exit 1
fi

REPO_URL="${ROUTERVAULT_REPO_URL:-$REPO_URL_DEFAULT}"
REPO_REF="${ROUTERVAULT_REPO_REF:-$REPO_REF_DEFAULT}"
INSTALL_DIR="${ROUTERVAULT_INSTALL_DIR:-$INSTALL_DIR_DEFAULT}"

echo "RouterVault installer"
echo

read -r -p "Install directory [${INSTALL_DIR}]: " _in_dir || true
if [[ -n "${_in_dir:-}" ]]; then
  INSTALL_DIR="$_in_dir"
fi

read -r -p "Git ref (branch/tag) [${REPO_REF}]: " _in_ref || true
if [[ -n "${_in_ref:-}" ]]; then
  REPO_REF="$_in_ref"
fi

echo
read -r -p "Initial username (non-deletable account): " BOOT_USER
BOOT_USER="$(echo "${BOOT_USER:-}" | xargs)"
if [[ -z "${BOOT_USER}" ]]; then
  echo "Username cannot be empty." >&2
  exit 1
fi

read -r -s -p "Initial password: " BOOT_PASS
echo
read -r -s -p "Confirm password: " BOOT_PASS_2
echo
if [[ -z "${BOOT_PASS}" ]]; then
  echo "Password cannot be empty." >&2
  exit 1
fi
if [[ "${BOOT_PASS}" != "${BOOT_PASS_2}" ]]; then
  echo "Passwords do not match." >&2
  exit 1
fi

echo
echo "Installing dependencies (git, curl, docker)..."

export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y --no-install-recommends ca-certificates curl git
  if ! command -v docker >/dev/null 2>&1; then
    apt-get install -y docker.io docker-compose-plugin
  else
    apt-get install -y docker-compose-plugin || true
  fi
else
  echo "Unsupported OS: this installer currently supports Debian/Ubuntu (apt-get)." >&2
  exit 1
fi

systemctl enable --now docker >/dev/null 2>&1 || true

echo
echo "Fetching RouterVault source..."
mkdir -p "$(dirname "${INSTALL_DIR}")"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
  git -C "${INSTALL_DIR}" fetch --all --prune
  git -C "${INSTALL_DIR}" checkout -f "${REPO_REF}"
  git -C "${INSTALL_DIR}" reset --hard "origin/${REPO_REF}" 2>/dev/null || true
else
  rm -rf "${INSTALL_DIR}"
  git clone --depth 1 --branch "${REPO_REF}" "${REPO_URL}" "${INSTALL_DIR}"
fi

cd "${INSTALL_DIR}"
mkdir -p ./data

echo
echo "Building Docker image..."
docker compose build

echo
echo "Bootstrapping first account..."
docker compose run --rm \
  -e ROUTERVAULT_BOOTSTRAP_USERNAME="${BOOT_USER}" \
  -e ROUTERVAULT_BOOTSTRAP_PASSWORD="${BOOT_PASS}" \
  routervault \
  python -c "from app.db import init_db; from app.services.config import settings; init_db(settings.db_path)"

echo
echo "Starting RouterVault..."
docker compose up -d --remove-orphans

echo
echo "Enabling auto-start on reboot..."
cat >/etc/systemd/system/routervault.service <<'UNIT'
[Unit]
Description=RouterVault (Docker Compose)
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/routervault
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
UNIT

if [[ "${INSTALL_DIR}" != "/opt/routervault" ]]; then
  sed -i "s|WorkingDirectory=/opt/routervault|WorkingDirectory=${INSTALL_DIR}|g" /etc/systemd/system/routervault.service
fi

systemctl daemon-reload
systemctl enable --now routervault.service >/dev/null 2>&1 || true

echo
echo "Done."
echo "RouterVault is running on port 8000."
echo "Login with the username/password you provided during installation."
