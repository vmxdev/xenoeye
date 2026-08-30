#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
source /etc/os-release
[[ ${ID} == debian && ${VERSION_ID%%.*} =~ ^(12|13)$ ]] || { echo "Debian 12 or 13 is required" >&2; exit 1; }

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg nginx
if ! command -v node >/dev/null || [[ $(node -p 'Number(process.versions.node.split(".")[0])') -lt 20 ]]; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" >/etc/apt/sources.list.d/nodesource.list
  apt-get update
  apt-get install -y nodejs
fi
cd "$ROOT_DIR/frontend"
npm install
npm run build
rm -rf /var/www/xenoeye
install -d /var/www/xenoeye
cp -a dist/. /var/www/xenoeye/
install -m 0644 "$ROOT_DIR/deploy/nginx/xenoeye.conf" /etc/nginx/sites-available/xenoeye
ln -sfn /etc/nginx/sites-available/xenoeye /etc/nginx/sites-enabled/xenoeye
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx
echo "Frontend installed: http://$(hostname -I | awk '{print $1}')/"

