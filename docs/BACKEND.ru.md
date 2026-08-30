# Back-end Xenoeye Portal

## Технологии

- Python 3.11+ (на Debian используются системные Python 3.11/3.13).
- FastAPI и Uvicorn.
- SQLAlchemy 2 и Psycopg 3.
- PostgreSQL 15+.
- JWT HS256 и Argon2 для хеширования паролей.

## Конфигурация

Все переменные имеют префикс `XE_`.

| Переменная | Назначение | Пример |
|---|---|---|
| `XE_DATABASE_URL` | DSN SQLAlchemy | `postgresql+psycopg://xenoeye:secret@localhost/xenoeyedb` |
| `XE_JWT_SECRET` | ключ подписи, минимум 32 символа | результат `openssl rand -hex 32` |
| `XE_ACCESS_TOKEN_MINUTES` | срок JWT | `480` |
| `XE_BOOTSTRAP_ADMIN_EMAIL` | email первого администратора | `admin@example.com` |
| `XE_BOOTSTRAP_ADMIN_PASSWORD` | пароль первого администратора | длинный случайный пароль |
| `XE_CORS_ORIGINS` | разрешённые origin через запятую | `https://flow.example.com` |

Первый администратор создаётся только если таблица пользователей пуста. Изменение bootstrap-пароля после этого не сбрасывает существующую запись.

## API

OpenAPI доступен на `/docs`, схема — `/openapi.json`.

### Аутентификация

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/api/v1/auth/token` | OAuth2 password form, полем username передаётся email |
| `GET` | `/api/v1/auth/me` | текущий пользователь |
| `POST` | `/api/v1/auth/change-password` | смена собственного пароля |
| `GET/PUT` | `/api/v1/auth/preferences` | настройки личного кабинета |

### Пользователи (только администратор)

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/v1/users` | список пользователей |
| `POST` | `/api/v1/users` | создать личный кабинет |
| `PATCH` | `/api/v1/users/{id}` | роль, статус, пароль и доступные таблицы |
| `DELETE` | `/api/v1/users/{id}` | удалить кабинет; свой удалить нельзя |

### Аналитика

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/v1/traffic/tables` | разрешённые таблицы и их поля |
| `GET` | `/api/v1/traffic/summary?hours=24` | KPI по доступным данным |
| `GET` | `/api/v1/traffic/series` | временной ряд метрики |
| `GET` | `/api/v1/traffic/top` | Top-N по измерению |

Пример:

```bash
TOKEN=$(curl -s -X POST http://localhost/api/v1/auth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=admin@example.com' \
  --data-urlencode 'password=your-password' | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" \
  'http://localhost/api/v1/traffic/series?table=mynet-ingress_total&metric=octets&bucket=5m'
```

## Локальная разработка

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
export XE_DATABASE_URL='postgresql+psycopg://xenoeye:password@localhost/xenoeyedb'
export XE_JWT_SECRET="$(openssl rand -hex 32)"
uvicorn app.main:app --reload
```

Тесты и статический анализ:

```bash
pytest
ruff check app tests
```

