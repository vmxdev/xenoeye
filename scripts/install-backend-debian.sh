#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
source /etc/os-release
[[ ${ID} == debian && ${VERSION_ID%%.*} =~ ^(12|13)$ ]] || { echo "Debian 12 or 13 is required" >&2; exit 1; }

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INSTALL_DIR=/opt/xenoeye
DB_PASSWORD=${XE_DB_PASSWORD:-$(openssl rand -hex 24)}
JWT_SECRET=${XE_JWT_SECRET:-$(openssl rand -hex 32)}
ADMIN_EMAIL=${XE_BOOTSTRAP_ADMIN_EMAIL:-admin@example.com}
ADMIN_PASSWORD=${XE_BOOTSTRAP_ADMIN_PASSWORD:-$(openssl rand -base64 24 | tr -d '/+=')}
[[ $DB_PASSWORD =~ ^[A-Za-z0-9._~-]+$ ]] || { echo "XE_DB_PASSWORD contains unsupported characters" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv postgresql openssl rsync
install -d "$INSTALL_DIR"
rsync -a --delete "$ROOT_DIR/backend/" "$INSTALL_DIR/backend/"
id xenoeye-api &>/dev/null || useradd --system --home "$INSTALL_DIR/backend" --shell /usr/sbin/nologin xenoeye-api
python3 -m venv "$INSTALL_DIR/backend/.venv"
"$INSTALL_DIR/backend/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/backend/.venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt"
chown -R xenoeye-api:xenoeye-api "$INSTALL_DIR/backend"

runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='xenoeye'" | grep -q 1 || runuser -u postgres -- psql -c "CREATE ROLE xenoeye LOGIN PASSWORD '$DB_PASSWORD'"
runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='xenoeyedb'" | grep -q 1 || runuser -u postgres -- createdb -O xenoeye xenoeyedb
runuser -u postgres -- psql -c "ALTER ROLE xenoeye PASSWORD '$DB_PASSWORD'"

install -d -m 0750 /etc/xenoeye-portal
cat >/etc/xenoeye-portal/backend.env <<EOF
XE_DATABASE_URL=postgresql+psycopg://xenoeye:${DB_PASSWORD}@localhost/xenoeyedb
XE_JWT_SECRET=${JWT_SECRET}
XE_BOOTSTRAP_ADMIN_EMAIL=${ADMIN_EMAIL}
XE_BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASSWORD}
XE_CORS_ORIGINS=http://localhost
EOF
chmod 0600 /etc/xenoeye-portal/backend.env
install -m 0644 "$ROOT_DIR/deploy/systemd/xenoeye-api.service" /etc/systemd/system/xenoeye-api.service
systemctl daemon-reload
systemctl enable --now xenoeye-api
cat >/root/xenoeye-initial-credentials.txt <<EOF
Xenoeye portal URL: http://$(hostname -I | awk '{print $1}')/
Admin email: ${ADMIN_EMAIL}
Admin password: ${ADMIN_PASSWORD}
EOF
chmod 0600 /root/xenoeye-initial-credentials.txt
echo "Backend installed. Initial credentials: /root/xenoeye-initial-credentials.txt"
