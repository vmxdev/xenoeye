#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
source /etc/os-release
[[ ${ID} == debian && ${VERSION_ID%%.*} =~ ^(12|13)$ ]] || { echo "Debian 12 or 13 is required" >&2; exit 1; }
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

apt-get update
apt-get install -y ca-certificates curl git gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

cd "$ROOT_DIR"
git submodule update --init --recursive
if [[ ! -f .env ]]; then
  DB_PASSWORD=$(openssl rand -hex 24)
  JWT_SECRET=$(openssl rand -hex 32)
  ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')
  cat >.env <<EOF
POSTGRES_DB=xenoeyedb
POSTGRES_USER=xenoeye
POSTGRES_PASSWORD=${DB_PASSWORD}
XE_JWT_SECRET=${JWT_SECRET}
XE_BOOTSTRAP_ADMIN_EMAIL=admin@example.com
XE_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASSWORD}
XE_CORS_ORIGINS=http://localhost:8080
XE_HTTP_PORT=8080
EOF
  chmod 0600 .env
  cat >/root/xenoeye-initial-credentials.txt <<EOF
Xenoeye portal URL: http://$(hostname -I | awk '{print $1}'):8080/
Admin email: admin@example.com
Admin password: ${ADMIN_PASSWORD}
EOF
  chmod 0600 /root/xenoeye-initial-credentials.txt
fi
docker compose up -d --build
docker compose ps
echo "Docker installation complete. Read credentials: /root/xenoeye-initial-credentials.txt"
