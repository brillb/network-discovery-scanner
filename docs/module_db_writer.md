# Database Writer (`module_db_writer.py`)

## Purpose
`module_db_writer.py` is the persistence layer for single-IP discovery results.

It now exposes two layers:

- `DatabaseWriter`
  - low-level table-specific write helpers
- `ScanResultWriter`
  - higher-level adapter that persists one completed `SingleIPScanResult`

## Current Write Model

The orchestrator no longer writes to the database from scan worker threads.

Instead:

1. a scan worker builds a `SingleIPScanResult`
2. the result is queued to a DB writer shard
3. `ScanResultWriter.persist_scan_result()` writes the result in one transaction

This is the core behavior that makes SQLite-safe parallel scanning possible.

## `DatabaseWriter`

`DatabaseWriter` still owns the table-specific rules for:

- ensuring a `devices` row exists
- writing reachability state
- upserting `device_inventory`
- updating `device_interfaces`
- inserting deduplicated `device_neighbors`
- inserting `device_configs`
- writing `devices.last_error`

It now also exposes `rollback()` so the higher-level writer can safely abort a failed transaction.

## `ScanResultWriter`

`ScanResultWriter` takes one open DB connection and translates a finished scan result into the underlying table writes.

Its flow is:

1. `ensure_device(ip)`
2. `record_reachability(...)` when reachability data exists
3. write SNMP success or failure state
4. write SSH success or failure state
5. write final `last_error`
6. commit once

If any step fails, it rolls the transaction back and re-raises the exception.

## Why One Commit Per IP

Compared with the old per-phase commit model, one commit per IP gives:

- less SQLite lock churn
- fewer remote SQL round trips
- simpler failure handling
- a cleaner boundary between network work and persistence work

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

