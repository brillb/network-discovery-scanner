# Database Loader (`db_loader.py`)

## Purpose
[`db_loader.py`](../src/db_loader.py) is the shared database access layer for the scanner and both browser tools.

It is responsible for:

- loading and validating `db.yaml`
- normalizing the database config into a predictable Python dictionary
- creating the SQLAlchemy engine for SQLite, MySQL, MariaDB, or PostgreSQL
- defining the shared schema metadata and table objects
- initializing the schema when requested
- applying lightweight schema updates required by newer code

This file is used by:

- [`scanner_orchestrator.py`](../src/scanner_orchestrator.py)
- [`process_single_ip.py`](../src/process_single_ip.py)
- [`tabular_browser.py`](../src/browser/tabular_browser.py)
- [`graphical_browser.py`](../src/browser/graphical_browser.py)

## What It Defines

### Shared table metadata
The module defines the SQLAlchemy table objects used throughout the application:

- `devices`
- `device_inventory`
- `device_interfaces`
- `device_neighbors`
- `device_configs`

These definitions are the canonical schema source for runtime initialization.

### `DatabaseHandle`
`DatabaseHandle` is a small dataclass returned by `load_database()`.

It contains:

- `config_path`: resolved absolute path to the YAML file
- `config`: normalized database config dictionary
- `engine`: SQLAlchemy engine
- `alias`: browser-safe database alias
- `display_name`: short readable name for UI display

## Main Functions

### `load_db_config(config_path)`
Reads the YAML file, validates its structure, and normalizes values.

Important behavior:

- requires exactly one top-level key named `db`
- supports `sqlite`, `mysql`, `mariadb`, and `postgresql`
- resolves relative SQLite `dbfile` paths relative to the config file location
- allows either `password` or `password_env`
- converts numeric fields like `port` and `connect_timeout` to integers

### `create_engine_from_config(db_config)`
Builds the SQLAlchemy engine from the normalized config.

Behavior by backend:

- `sqlite`: creates parent directories automatically and uses `check_same_thread=False`
- `postgresql`: uses `postgresql+psycopg`
- `mysql` and `mariadb`: use `mysql+pymysql`

It also passes backend-specific query settings such as:

- `connect_timeout`
- `charset` for MySQL and MariaDB
- `sslmode` for PostgreSQL

### `initialize_database(engine)`
Creates all known tables from the SQLAlchemy metadata and applies lightweight schema updates when needed.

Current migration behavior includes:

- ensuring `device_inventory.working_ssh_credential` exists on older databases

This keeps older scanner databases compatible with newer code without requiring a separate migration framework.

### `load_database(config_path, initialize=False)`
This is the main entry point used by the rest of the project.

It:

1. loads and validates the YAML config
2. creates the engine
3. optionally initializes the schema
4. returns a `DatabaseHandle`

## Helper Functions

### `describe_database(db_config)`
Returns a readable description of the target database.

Examples:

- SQLite: absolute path to the `.sqlite` file
- PostgreSQL: `postgresql://host:port/database`

This is primarily used by the browsers and orchestrator for status output.

### `get_database_display_name(db_config)`
Returns a short display string for UI use.

Examples:

- SQLite: `discovery_results.sqlite`
- PostgreSQL: `postgresql:discovery_inventory@db.example.com:5432`

### `get_database_alias(db_config)`
Builds a sanitized alias suitable for use in browser URLs and internal routing.

## How The Scanner Uses It

The normal runtime flow is:

1. A script receives `--dbconfig /path/to/db.yaml`.
2. It calls `load_database(..., initialize=True)`.
3. The engine is created and the schema is created if missing.
4. The caller uses the shared table objects or raw SQL against that engine.

Examples in this repo:

- the orchestrator uses it to validate the target backend before dispatching work
- the single-IP worker uses it to update device records and evidence metadata
- the browsers use it to connect to the configured database and display results

## Database Setup Examples

These examples are copied from [`GETTING_STARTED.md`](../GETTING_STARTED.md).

### SQLite example

```yaml
db:
  type: sqlite
  dbfile: scan_results/discovery_results.sqlite
```

### PostgreSQL example

```yaml
db:
  type: postgresql
  host: db.example.com
  port: 5432
  database: discovery_inventory
  username: scanner_user
  password_env: DISCOVERY_DB_PASSWORD
  ssl_mode: require
  connect_timeout: 10
```

### MySQL or MariaDB example

```yaml
db:
  type: mariadb
  host: db.example.com
  port: 3306
  database: discovery_inventory
  username: scanner_user
  password: change_me
  charset: utf8mb4
  connect_timeout: 10
```

## Sample Config Files

Sample files are available here:

- [`db-local-sqlite.yaml`](sample_config_files/db-local-sqlite.yaml)
- [`db-mysql.yaml`](sample_config_files/db-mysql.yaml)
- [`db-postgresql.yaml`](sample_config_files/db-postgresql.yaml)

## Notes

- Remote databases must already exist before the scanner connects.
- The scanner can create its tables automatically, but it does not create the remote database itself.
- SQLite is appropriate for local serial scans.
- Parallel scanning is intended for PostgreSQL, MySQL, and MariaDB rather than SQLite.

---

## Attribution and License

Copyright 2026 Benjamin Brillat

Author: Benjamin Brillat  
GitHub: [brillb](https://github.com/brillb)

This document is part of the `brillb/network-discovery-scanner` project.

Co-authored using AI coding assist modules in the IDE, including GPT,
Copilot, Gemini, and similar tools.

Licensed under the Apache License, Version 2.0. You may obtain a copy of the
license in the repository `LICENSE` file or at:
<https://www.apache.org/licenses/LICENSE-2.0>

SPDX-License-Identifier: Apache-2.0

