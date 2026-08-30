from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import User
from ..schemas import Summary, TableInfo
from ..security import get_current_user
from ..services.traffic import accessible_tables, get_series, get_summary, get_top

router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("/tables", response_model=list[TableInfo])
def tables(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[TableInfo]:
    return accessible_tables(user, db.get_bind())


@router.get("/summary", response_model=Summary)
def summary(
    hours: int = Query(default=24, ge=1, le=24 * 90),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Summary:
    return get_summary(db, user, hours)


@router.get("/series")
def series(
    table: str,
    metric: str = "octets",
    start: datetime = Query(default_factory=lambda: datetime.now(UTC) - timedelta(hours=24)),
    end: datetime = Query(default_factory=lambda: datetime.now(UTC)),
    bucket: str = "5m",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return get_series(db, user, table, metric, start, end, bucket)


@router.get("/top")
def top(
    table: str,
    dimension: str,
    metric: str = "octets",
    start: datetime = Query(default_factory=lambda: datetime.now(UTC) - timedelta(hours=24)),
    end: datetime = Query(default_factory=lambda: datetime.now(UTC)),
    limit: int = Query(default=10, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    return get_top(db, user, table, metric, dimension, start, end, limit)

