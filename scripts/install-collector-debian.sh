#!/usr/bin/env bash
set -Eeuo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root: sudo $0" >&2; exit 1; }
source /etc/os-release
[[ ${ID} == debian && ${VERSION_ID%%.*} =~ ^(12|13)$ ]] || { echo "Debian 12 or 13 is required" >&2; exit 1; }

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y git autoconf automake gcc make libpcap-dev libtool libatomic1 libcap2-bin postgresql-client rsync

git -C "$ROOT_DIR" submodule update --init --recursive
cd "$ROOT_DIR"
autoreconf -i
./configure --sysconfdir=/etc/xenoeye --localstatedir=/var/lib --libexecdir=/var/lib/xenoeye/scripts
make -j"$(nproc)"
make check
make install

id xenoeye &>/dev/null || useradd --system --home /var/lib/xenoeye --shell /usr/sbin/nologin xenoeye
install -d -o xenoeye -g xenoeye /var/lib/xenoeye/{mo,exp,expfailed,iplists,notifications,clsf,geoip}
chown -R xenoeye:xenoeye /var/lib/xenoeye
install -m 0644 "$ROOT_DIR/deploy/systemd/xenoeye.service" /etc/systemd/system/xenoeye.service
cat >/etc/xenoeye/collector.env <<EOF
XE_DATABASE_DSN=postgresql://xenoeye:${XE_DB_PASSWORD:-password}@localhost/xenoeyedb
EOF
chmod 0600 /etc/xenoeye/collector.env
systemctl daemon-reload
systemctl enable --now xenoeye
echo "Collector installed. UDP ports: 2055 (NetFlow/IPFIX), 6343 (sFlow)."

