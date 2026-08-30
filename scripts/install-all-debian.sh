#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

export XE_DB_PASSWORD=${XE_DB_PASSWORD:-$(openssl rand -hex 24)}
"$ROOT_DIR/scripts/install-backend-debian.sh"
"$ROOT_DIR/scripts/install-collector-debian.sh"
"$ROOT_DIR/scripts/install-frontend-debian.sh"
echo "Installation complete. Read credentials: sudo cat /root/xenoeye-initial-credentials.txt"

