# Copyright 2026 Benjamin Brillat
#
# Author: Benjamin Brillat
# GitHub: https://github.com/brillb
# License: Apache License 2.0
# SPDX-License-Identifier: Apache-2.0
#
# This file is part of the brillb/network-discovery-scanner project.
#
# Co-authored using AI coding assist modules in the IDE, including
# GPT, Copilot, Gemini, and similar tools.
#
# See the LICENSE file at the repository root for full license terms.

import os
import re
from dataclasses import dataclass

import yaml
from sqlalchemy import Boolean, Column, ForeignKey, Integer, MetaData, Table, Text, create_engine, inspect, text
from sqlalchemy.engine import URL
from sqlalchemy import event


SUPPORTED_DB_TYPES = {"sqlite", "mysql", "mariadb", "postgresql"}

metadata = MetaData()

devices = Table(
    "devices",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ip_address", Text, unique=True),
    Column("scan_time", Text),
    Column("is_alive", Boolean),
    Column("ping_responded", Boolean),
    Column("ssh_port_open", Boolean),
    Column("snmp_responded", Boolean),
    Column("ssh_responded", Boolean),
    Column("last_error", Text),
)

device_inventory = Table(
    "device_inventory",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("device_id", Integer, ForeignKey("devices.id")),
    Column("hostname", Text),
    Column("hardware_product", Text),
    Column("model", Text),
    Column("hardware_version", Text),
    Column("software_image", Text),
    Column("software_version", Text),
    Column("serial_number", Text),
    Column("uptime_seconds", Integer),
    Column("power_status", Text),
    Column("working_snmp_credential", Text),
    Column("working_ssh_credential", Text),
)

device_interfaces = Table(
    "device_interfaces",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("device_id", Integer, ForeignKey("devices.id")),
    Column("interface_name", Text),
    Column("ip_address", Text),
    Column("subnet_mask", Text),
)

device_neighbors = Table(
    "device_neighbors",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("device_id", Integer, ForeignKey("devices.id")),
    Column("neighbor_hostname", Text),
    Column("neighbor_ip", Text),
    Column("local_port", Text),
    Column("remote_port", Text),
    Column("protocol", Text),
)

device_configs = Table(
    "device_configs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("device_id", Integer, ForeignKey("devices.id")),
    Column("working_ssh_credential", Text),
    Column("evidence_file_path", Text),
)


@dataclass
class DatabaseHandle:
    config_path: str
    config: dict
    engine: object
    alias: str
    display_name: str


def _require_mapping(value, message):
    if not isinstance(value, dict):
        raise ValueError(message)
    return value


def _resolve_password(db_config):
    password = db_config.get("password")
    password_env = db_config.get("password_env")

    if password:
        return password

    if password_env:
        resolved = os.environ.get(password_env)
        if resolved is None:
            raise ValueError(f"Environment variable {password_env!r} was not set for database password resolution.")
        return resolved

    return None


def load_db_config(config_path):
    resolved_config_path = os.path.abspath(config_path)

    with open(resolved_config_path, "r", encoding="utf-8") as handle:
        raw_config = yaml.safe_load(handle) or {}

    _require_mapping(raw_config, "Database config must be a YAML mapping.")
    if set(raw_config.keys()) != {"db"}:
        raise ValueError("Database config must contain exactly one top-level key named 'db'.")

    db_config = _require_mapping(raw_config["db"], "The 'db' section must be a YAML mapping.")
    db_type = str(db_config.get("type", "")).strip().lower()

    if db_type not in SUPPORTED_DB_TYPES:
        raise ValueError(f"Unsupported database type {db_type!r}. Supported types: {', '.join(sorted(SUPPORTED_DB_TYPES))}.")

    normalized = {"type": db_type, "config_path": resolved_config_path}

    if db_type == "sqlite":
        dbfile = str(db_config.get("dbfile", "")).strip()
        if not dbfile:
            raise ValueError("SQLite config requires 'dbfile'.")

        if os.path.isabs(dbfile):
            resolved_dbfile = dbfile
        else:
            resolved_dbfile = os.path.abspath(os.path.join(os.path.dirname(resolved_config_path), dbfile))

        normalized["dbfile"] = resolved_dbfile
        return normalized

    for field_name in ("host", "database"):
        field_value = str(db_config.get(field_name, "")).strip()
        if not field_value:
            raise ValueError(f"{db_type} config requires '{field_name}'.")
        normalized[field_name] = field_value

    if db_config.get("port") not in (None, ""):
        normalized["port"] = int(db_config["port"])

    for optional_field in ("username", "charset", "ssl_mode"):
        field_value = db_config.get(optional_field)
        if field_value not in (None, ""):
            normalized[optional_field] = str(field_value)

    if db_config.get("connect_timeout") not in (None, ""):
        normalized["connect_timeout"] = int(db_config["connect_timeout"])

    password = _resolve_password(db_config)
    if password is not None:
        normalized["password"] = password

    return normalized


def get_database_display_name(db_config):
    if db_config["type"] == "sqlite":
        return os.path.basename(db_config["dbfile"])

    host = db_config["host"]
    port = db_config.get("port")
    port_suffix = f":{port}" if port else ""
    return f"{db_config['type']}:{db_config['database']}@{host}{port_suffix}"


def get_database_alias(db_config):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", get_database_display_name(db_config)).strip("_") or "database"


def describe_database(db_config):
    if db_config["type"] == "sqlite":
        return db_config["dbfile"]

    host = db_config["host"]
    port = db_config.get("port")
    port_suffix = f":{port}" if port else ""
    return f"{db_config['type']}://{host}{port_suffix}/{db_config['database']}"


def _configure_sqlite_connection(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def create_engine_from_config(db_config, *, pool_size=None, max_overflow=None):
    db_type = db_config["type"]

    if db_type == "sqlite":
        dbfile = db_config["dbfile"]
        parent_dir = os.path.dirname(dbfile)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        engine = create_engine(
            URL.create("sqlite", database=dbfile),
            future=True,
            connect_args={"check_same_thread": False},
        )
        event.listen(engine, "connect", _configure_sqlite_connection)
        return engine

    query = {}
    if "connect_timeout" in db_config:
        query["connect_timeout"] = str(db_config["connect_timeout"])
    if db_type in {"mysql", "mariadb"} and "charset" in db_config:
        query["charset"] = db_config["charset"]
    if db_type == "postgresql" and "ssl_mode" in db_config:
        query["sslmode"] = db_config["ssl_mode"]

    driver_name = "postgresql+psycopg" if db_type == "postgresql" else "mysql+pymysql"
    engine_kwargs = {
        "future": True,
        "pool_pre_ping": True,
    }
    if pool_size is not None:
        engine_kwargs["pool_size"] = int(pool_size)
    if max_overflow is not None:
        engine_kwargs["max_overflow"] = int(max_overflow)

    return create_engine(
        URL.create(
            driver_name,
            username=db_config.get("username"),
            password=db_config.get("password"),
            host=db_config["host"],
            port=db_config.get("port"),
            database=db_config["database"],
            query=query,
        ),
        **engine_kwargs,
    )


def initialize_database(engine):
    metadata.create_all(engine)

    required_columns = {
        "device_inventory": {
            "working_ssh_credential": "TEXT",
        },
    }

    inspector = inspect(engine)
    with engine.begin() as conn:
        for table_name, columns in required_columns.items():
            if not inspector.has_table(table_name):
                continue

            existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, column_type in columns.items():
                if column_name in existing_columns:
                    continue
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))


def load_database(config_path, initialize=False, *, pool_size=None, max_overflow=None):
    db_config = load_db_config(config_path)
    engine = create_engine_from_config(
        db_config,
        pool_size=pool_size,
        max_overflow=max_overflow,
    )

    if initialize:
        initialize_database(engine)

    return DatabaseHandle(
        config_path=os.path.abspath(config_path),
        config=db_config,
        engine=engine,
        alias=get_database_alias(db_config),
        display_name=get_database_display_name(db_config),
    )
