from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="XE_", extra="ignore")

    app_name: str = "Xenoeye API"
    api_prefix: str = "/api/v1"
    database_url: str = "postgresql+psycopg://xenoeye:password@localhost/xenoeyedb"
    jwt_secret: str = Field(min_length=32, default="change-this-secret-before-production-123456")
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 480
    bootstrap_admin_email: str = "admin@example.com"
    bootstrap_admin_password: str = "ChangeMe123!"
    cors_origins: str = "http://localhost:5173,http://localhost:8080"

    @property
    def cors_origin_list(self) -> list[str]:
        return [value.strip() for value in self.cors_origins.split(",") if value.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
