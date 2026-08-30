from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db import engine
from app.main import app


def test_health_and_authentication() -> None:
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        login = client.post(
            "/api/v1/auth/token",
            data={"username": "admin@example.com", "password": "TestPassword123!"},
        )
        assert login.status_code == 200
        token = login.json()["access_token"]

        profile = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert profile.status_code == 200
        assert profile.json()["is_admin"] is True

        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE mynet_total (time DATETIME, packets BIGINT, octets BIGINT)")
            )
            connection.execute(text("INSERT INTO mynet_total VALUES (CURRENT_TIMESTAMP, 10, 100)"))
            connection.execute(
                text(
                    "CREATE TABLE mynet_proto "
                    "(time DATETIME, packets BIGINT, octets BIGINT, proto BIGINT)"
                )
            )
            connection.execute(text("INSERT INTO mynet_proto VALUES (CURRENT_TIMESTAMP, 10, 100, 6)"))

        summary = client.get(
            "/api/v1/traffic/summary", headers={"Authorization": f"Bearer {token}"}
        )
        assert summary.status_code == 200
        assert summary.json()["bytes"] == 100
        assert summary.json()["packets"] == 10
