# Установка Xenoeye Portal

## Требования

- Debian 12 (Bookworm) или Debian 13 (Trixie), x86_64/AArch64.
- root или `sudo`.
- открытые UDP 2055 для NetFlow/IPFIX и UDP 6343 для sFlow.
- открытый TCP 80/8080 для web-интерфейса.
- минимум 2 CPU, 2 ГБ RAM и 20 ГБ диска для небольшой инсталляции.

Для нагруженной сети размер ресурсов определяется количеством flow/s, объектами мониторинга, глубиной истории и индексами PostgreSQL.

## Вариант 1: автоматическая установка на Debian

```bash
git clone --recurse-submodules https://github.com/In0tech/xenoeye.git
cd xenoeye
sudo ./scripts/install-all-debian.sh
sudo cat /root/xenoeye-initial-credentials.txt
```

Скрипт:

1. устанавливает и тестирует C-коллектор;
2. создаёт системных пользователей `xenoeye` и `xenoeye-api`;
3. устанавливает PostgreSQL и создаёт БД;
4. разворачивает Python venv и systemd API;
5. устанавливает Node.js 22, собирает React и настраивает Nginx;
6. генерирует отдельные пароли БД, JWT и администратора.

Секреты сохраняются с правами `0600`. После первого входа смените пароль администратора.

Проверка:

```bash
systemctl status xenoeye xenoeye-api nginx postgresql
curl http://127.0.0.1:8000/health
ss -lunp | grep -E ':2055|:6343'
```

Компоненты можно установить отдельно:

```bash
sudo ./scripts/install-collector-debian.sh
sudo ./scripts/install-backend-debian.sh
sudo ./scripts/install-frontend-debian.sh
```

Для заранее заданных секретов передайте переменные в окружении root:

```bash
sudo env \
  XE_DB_PASSWORD='long-alphanumeric-password' \
  XE_JWT_SECRET='at-least-32-random-characters-long' \
  XE_BOOTSTRAP_ADMIN_EMAIL='admin@example.com' \
  XE_BOOTSTRAP_ADMIN_PASSWORD='StrongInitialPassword123!' \
  ./scripts/install-all-debian.sh
```

## Вариант 2: Docker Compose

Автоматически установить Docker Engine и запустить стек:

```bash
git clone --recurse-submodules https://github.com/In0tech/xenoeye.git
cd xenoeye
sudo ./scripts/install-docker-debian.sh
sudo cat /root/xenoeye-initial-credentials.txt
```

Ручной запуск при уже установленном Docker:

```bash
cp .env.example .env
editor .env                 # обязательно заменить все секреты
editor deploy/docker/iplists/mynet
editor deploy/docker/devices.conf
docker compose up -d --build
docker compose ps
docker compose logs -f collector backend
```

Интерфейс доступен на `http://SERVER:8080`. Порт меняется переменной `XE_HTTP_PORT`.

Compose создаёт:

- `collector` — C-коллектор;
- `postgres` — хранилище;
- `backend` — API личных кабинетов;
- `frontend` — Nginx и React.

PostgreSQL не публикуется наружу. Сервисы общаются по внутренней сети Compose. Данные находятся в named volumes `postgres-data` и `collector-state`.

### Обновление контейнерной установки

```bash
git pull --ff-only
git submodule update --init --recursive
docker compose up -d --build
docker image prune -f
```

### Резервное копирование

```bash
docker compose exec -T postgres pg_dump -U xenoeye -Fc xenoeyedb > xenoeye-$(date +%F).dump
docker run --rm -v xenoeye_collector-state:/data -v "$PWD":/backup alpine \
  tar czf /backup/xenoeye-state-$(date +%F).tar.gz -C /data .
```

## Первичная настройка трафика

1. В `devices.conf` укажите IP экспортёров и sampling rate.
2. В `iplists/mynet` перечислите свои IPv4/IPv6 сети.
3. Создайте или измените объекты мониторинга `mo/*/mo.conf`.
4. Настройте маршрутизатор отправлять NetFlow/IPFIX на UDP 2055 или sFlow на UDP 6343.
5. Убедитесь, что таблицы появились в разделе «Аналитика».

В Docker стартовые объекты создают ingress/egress таблицы total, proto, sources, destinations и routers. Обязательно замените тестовые сети `10.0.0.0/8` и `192.168.0.0/16` своими.

## TLS

Для production разместите сервис за HTTPS. Например, установите Certbot и замените `server_name _` в `/etc/nginx/sites-available/xenoeye` реальным DNS-именем:

```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d flows.example.com
```

После включения HTTPS установите `XE_CORS_ORIGINS=https://flows.example.com` в `/etc/xenoeye-portal/backend.env` и перезапустите API.

## Диагностика

```bash
journalctl -u xenoeye -u xenoeye-api -n 200 --no-pager
tail -f /var/log/nginx/error.log
psql postgresql://xenoeye@localhost/xenoeyedb -c '\dt'
ls -lah /var/lib/xenoeye/exp /var/lib/xenoeye/expfailed
```

Если `expfailed` заполняется, проверьте `XE_DATABASE_DSN`, пароль роли PostgreSQL и доступность БД. Если таблицы есть, но кабинет пуст, проверьте назначение таблиц пользователю в административном разделе.

