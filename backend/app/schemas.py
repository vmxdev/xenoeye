from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserBase(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=160)
    is_active: bool = True
    is_admin: bool = False
    allowed_tables: list[str] = Field(default_factory=list)


class UserCreate(UserBase):
    password: str = Field(min_length=10, max_length=128)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=160)
    password: str | None = Field(default=None, min_length=10, max_length=128)
    is_active: bool | None = None
    is_admin: bool | None = None
    allowed_tables: list[str] | None = None


class UserOut(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=128)


class PreferenceIn(BaseModel):
    dashboard: dict[str, Any] = Field(default_factory=dict)
    theme: str = Field(default="dark", pattern="^(dark|light|system)$")


class PreferenceOut(PreferenceIn):
    model_config = ConfigDict(from_attributes=True)


class ColumnInfo(BaseModel):
    name: str
    data_type: str
    numeric: bool


class TableInfo(BaseModel):
    name: str
    columns: list[ColumnInfo]


class Summary(BaseModel):
    bytes: int = 0
    packets: int = 0
    flows: int = 0
    active_tables: int = 0
    last_data_at: datetime | None = None

