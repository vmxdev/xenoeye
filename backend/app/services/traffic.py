from datetime import datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from ..models import User
from ..schemas import ColumnInfo, Summary, TableInfo

SYSTEM_TABLES = {"xe_portal_users", "xe_portal_preferences", "alembic_version"}
NUMERIC_TYPES = {"smallint", "integer", "bigint", "decimal", "numeric", "real", "double precision"}
BUCKETS = {
    "1m": "date_trunc('minute', time)",
    "5m": "to_timestamp(floor(extract(epoch from time) / 300) * 300)",
    "1h": "date_trunc('hour', time)",
    "1d": "date_trunc('day', time)",
}


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def discover_tables(engine: Engine) -> list[TableInfo]:
    inspector = inspect(engine)
    schema = "public" if engine.dialect.name == "postgresql" else None
    result: list[TableInfo] = []
    for name in sorted(inspector.get_table_names(schema=schema)):
        if name in SYSTEM_TABLES:
            continue
        columns = inspector.get_columns(name, schema=schema)
        if not any(column["name"] == "time" for column in columns):
            continue
        result.append(
            TableInfo(
                name=name,
                columns=[
                    ColumnInfo(
                        name=column["name"],
                        data_type=str(column["type"]).lower(),
                        numeric=any(kind in str(column["type"]).lower() for kind in NUMERIC_TYPES),
                    )
                    for column in columns
                ],
            )
        )
    return result


def accessible_tables(user: User, engine: Engine) -> list[TableInfo]:
    tables = discover_tables(engine)
    if user.is_admin or "*" in user.allowed_tables:
        return tables
    allowed = set(user.allowed_tables)
    return [table for table in tables if table.name in allowed]


def get_accessible_table(user: User, engine: Engine, table_name: str) -> TableInfo:
    table = next((item for item in accessible_tables(user, engine) if item.name == table_name), None)
    if table is None:
        raise HTTPException(status_code=404, detail="Table not found or access denied")
    return table


def require_column(table: TableInfo, column: str, numeric: bool = False) -> ColumnInfo:
    item = next((candidate for candidate in table.columns if candidate.name == column), None)
    if item is None or (numeric and not item.numeric):
        raise HTTPException(status_code=400, detail=f"Unsupported column: {column}")
    return item


def get_summary(db: Session, user: User, hours: int = 24) -> Summary:
    tables = accessible_tables(user, db.get_bind())
    result = Summary(active_tables=len(tables))
    since = datetime.now().astimezone() - timedelta(hours=hours)
    for table in tables:
        column_names = {column.name for column in table.columns}
        is_rollup = not (column_names - {"time", "octets", "packets", "bits", "flows"})
        select_parts = ["count(*) AS flows", "max(time) AS last_data_at"]
        select_parts.append(
            "coalesce(sum(octets), 0) AS bytes"
            if is_rollup and "octets" in column_names
            else "0 AS bytes"
        )
        select_parts.append(
            "coalesce(sum(packets), 0) AS packets"
            if is_rollup and "packets" in column_names
            else "0 AS packets"
        )
        statement = text(
            f"SELECT {', '.join(select_parts)} FROM {quote_identifier(table.name)} WHERE time >= :since"
        )
        row = db.execute(statement, {"since": since}).mappings().one()
        result.bytes += int(row["bytes"] or 0)
        result.packets += int(row["packets"] or 0)
        result.flows += int(row["flows"] or 0)
        if row["last_data_at"] and (result.last_data_at is None or row["last_data_at"] > result.last_data_at):
            result.last_data_at = row["last_data_at"]
    return result


def get_series(
    db: Session,
    user: User,
    table_name: str,
    metric: str,
    start: datetime,
    end: datetime,
    bucket: str,
) -> list[dict[str, Any]]:
    table = get_accessible_table(user, db.get_bind(), table_name)
    require_column(table, metric, numeric=True)
    bucket_expr = BUCKETS.get(bucket)
    if bucket_expr is None:
        raise HTTPException(status_code=400, detail="Unsupported bucket")
    statement = text(
        f"SELECT {bucket_expr} AS time, coalesce(sum({quote_identifier(metric)}), 0) AS value "
        f"FROM {quote_identifier(table.name)} WHERE time BETWEEN :start AND :end "
        "GROUP BY 1 ORDER BY 1 LIMIT 5000"
    )
    return [dict(row) for row in db.execute(statement, {"start": start, "end": end}).mappings()]


def get_top(
    db: Session,
    user: User,
    table_name: str,
    metric: str,
    dimension: str,
    start: datetime,
    end: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    table = get_accessible_table(user, db.get_bind(), table_name)
    require_column(table, metric, numeric=True)
    require_column(table, dimension)
    statement = text(
        f"SELECT cast({quote_identifier(dimension)} AS text) AS label, "
        f"coalesce(sum({quote_identifier(metric)}), 0) AS value "
        f"FROM {quote_identifier(table.name)} WHERE time BETWEEN :start AND :end "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT :limit"
    )
    params = {"start": start, "end": end, "limit": limit}
    return [dict(row) for row in db.execute(statement, params).mappings()]
