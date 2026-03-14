# Threading And Refactor Proposal

## Goal
Refactor the scanner so that:

1. `process_single_ip` becomes an importable pipeline instead of a subprocess-only script.
2. discovery work can run highly parallel while database writes remain safe for both SQLite and external SQL backends.
3. concurrency is controlled by two CLI knobs:
   - `--max-workers-per-db-connection`
   - `--max-db-connections`

This should allow a configuration like:

- SQLite: `1` DB connection, `20` scan workers behind it
- PostgreSQL/MySQL/MariaDB: `25` DB connections, `20` scan workers per connection
- Effective active scan concurrency: `25 * 20 = 500`

## Current Bottlenecks

The current design couples network work and database work too tightly:

- `scanner_orchestrator.py` launches one subprocess per IP.
- each `process_single_ip.py` child parses YAML again.
- each child creates its own SQLAlchemy engine/connection.
- each child writes directly to the database after each phase.
- SQLite is forced into serial execution because writes happen inside every worker.

This is why the old `--parallel` flag only worked with external databases.

## Recommended Direction

I recommend a class-based `process_single_ip` module and a threaded in-process orchestrator.

### 1. Refactor `process_single_ip.py` into an importable class

Keep the file, but turn it into a reusable pipeline module.

Recommended shape:

```python
@dataclass
class SingleIPScanRequest:
    ip: str
    keytags: list[str]


@dataclass
class SingleIPScanResult:
    ip: str
    started_at: str
    finished_at: str
    reachability: dict
    snmp: dict | None
    ssh: dict | None
    errors: list[str]


class SingleIPPipeline:
    def __init__(self, *, keys_data, ssh_commands_data, evidence_dir):
        ...

    def run(self, request: SingleIPScanRequest) -> SingleIPScanResult:
        ...
```

Important design rule:

- `SingleIPPipeline.run()` should do network work and build a result object.
- it should not own a live database connection.

That separation is the key enabler for SQLite-safe parallelism.

### 2. Keep `process_single_ip.py` as a CLI wrapper for compatibility

The existing CLI can remain, but `main()` should become thin:

1. parse args
2. load YAML
3. instantiate `SingleIPPipeline`
4. run one target
5. persist the returned result through the DB writer

That preserves current standalone behavior while allowing `scanner_orchestrator.py` to import the same pipeline directly.

## Proposed Concurrency Model

### Summary

Use one process, with:

- a target queue
- a scan worker pool
- a result queue per DB writer
- one dedicated writer thread per DB connection

### Core rule

Workers do network discovery.

Writer threads do database writes.

No worker thread should directly use a shared database connection.

### Why this works

For SQLite:

- `max_db_connections = 1`
- one writer thread owns the only connection
- many scan workers can still run in parallel
- all writes are serialized through one queue

For external SQL backends:

- each writer thread owns one connection
- results are sharded across writer queues
- total write concurrency is capped by `max_db_connections`
- total scan concurrency is `max_db_connections * max_workers_per_db_connection`

## Recommended Scheduler Layout

### Orchestrator threads

1. main thread
   - parse CLI
   - load shared YAML once
   - expand CSV/subnets into target work items
   - maintain inflight/completed bookkeeping
2. scan worker pool
   - `ThreadPoolExecutor` or fixed worker threads
   - runs `SingleIPPipeline.run(request)`
3. writer shard threads
   - one thread per DB connection
   - each owns exactly one SQLAlchemy connection
   - each drains one queue and persists results

### Result sharding

Each target IP should always map to the same writer shard for a given run.

Recommended mapping:

```python
writer_index = hash(ip_address) % max_db_connections
```

Benefits:

- all writes for one device stay ordered
- duplicate scans of the same IP do not bounce across DB connections
- contention is spread across connections for external DBs

## Database Write Strategy

### Recommended write granularity

Persist one `SingleIPScanResult` per IP in one transaction.

That is more efficient than the current pattern of committing after each phase.

Recommended transaction flow:

1. `ensure_device(ip)`
2. write reachability fields
3. write SNMP outcome and inventory data
4. write SSH outcome and evidence metadata
5. write final `last_error`
6. commit once

### Why I prefer one commit per IP

- far less lock churn for SQLite
- fewer round trips to remote SQL databases
- simpler failure semantics
- easier batching later if needed

If you want near-real-time progress visibility later, that can be added as phase events. I would not start there.

## CLI Proposal

Add these flags to `scanner_orchestrator.py`:

```text
--max-workers-per-db-connection INT
--max-db-connections INT
```

### Semantics

`--max-workers-per-db-connection`

- positive integer
- how many concurrent IP scans are allowed for each DB writer shard

`--max-db-connections`

- positive integer
- number of dedicated DB writer threads/connections

Derived value:

```text
effective_max_active_scans =
    max-workers-per-db-connection * max-db-connections
```

### Validation rules

For SQLite:

- `--max-db-connections` must resolve to `1`
- reject values greater than `1`

For PostgreSQL/MySQL/MariaDB:

- allow values greater than `1`
- set SQLAlchemy pool size to `max_db_connections`
- set `max_overflow=0` so the scanner does not exceed its advertised connection budget

### Suggested defaults

Safe first defaults:

- `--max-workers-per-db-connection 10`
- `--max-db-connections 1`

That keeps the first release conservative while still unlocking threaded SQLite scans.

## Proposed Refactor Of `module_db_writer.py`

The current writer is connection-oriented, which is fine, but it is too phase-oriented for the new design.

I would keep `DatabaseWriter`, but add a higher-level persistence entry point:

```python
class ScanResultWriter:
    def __init__(self, db_conn):
        self.writer = DatabaseWriter(db_conn)

    def persist_scan_result(self, result: SingleIPScanResult) -> None:
        ...
```

Responsibilities:

- translate `SingleIPScanResult` into DB writes
- keep the existing table-specific logic in `DatabaseWriter`
- commit once per IP

This keeps the DB logic centralized and avoids pushing SQL knowledge back into the orchestrator.

## Orchestrator Refactor Proposal

### Current model

- CSV row
- maybe subnet sweep
- spawn subprocess

### Proposed model

- CSV row
- maybe subnet sweep
- enqueue `SingleIPScanRequest`
- worker runs in-thread pipeline
- worker pushes `SingleIPScanResult` to the correct writer queue
- writer thread persists result

### Important improvement: input dedupe

The refactor should also add an `inflight_or_completed_ips` set.

Reason:

- overlapping subnets and duplicate CSV rows can currently schedule the same IP more than once
- with high parallelism, duplicate work will waste SSH/SNMP attempts and create noisy evidence output

Recommended behavior:

- skip duplicate IPs within a run unless a future `--allow-duplicate-targets` flag is added

## SQLite-Specific Recommendations

SQLite can work well here if we treat it as:

- one writer connection
- many network workers
- short transactions

I also recommend setting SQLite connection/session tuning when the backend is SQLite:

- `PRAGMA journal_mode=WAL`
- `PRAGMA synchronous=NORMAL`
- `PRAGMA busy_timeout=5000`

Those settings reduce writer stalls and make the single-writer model more resilient on a laptop.

## External Database Recommendations

For PostgreSQL/MySQL/MariaDB:

- configure the SQLAlchemy engine pool to exactly the requested writer count
- one long-lived connection per writer thread is preferred over connect/disconnect per result
- consider a small retry wrapper for transient commit errors

I would not let scan workers open ad hoc connections. That defeats the point of the connection budget.

## Backward Compatibility

I recommend this transition path:

### Phase 1

- convert `process_single_ip.py` into a class-backed importable module
- keep CLI wrapper behavior intact
- keep orchestrator serial

### Phase 2

- move orchestrator from subprocess dispatch to in-process threaded dispatch
- support SQLite with `1` writer thread and many scan workers

### Phase 3

- add multi-writer sharding for external SQL backends
- add the two new CLI knobs
- remove `--parallel`

### `--parallel` migration

Implemented option:

- remove `--parallel` entirely and replace it with the two explicit concurrency knobs

## Risks And Edge Cases

### 1. Thread safety of network modules

`module_ping`, `module_snmp`, `module_ssh`, and `module_portscan` should be reviewed for shared mutable globals.

The target design assumes:

- each scan call creates its own network/session objects
- no shared mutable connection state lives at module level

### 2. Evidence filename collisions

If the same IP can be scanned twice quickly, filename generation should include enough entropy.

Safer options:

- current timestamp plus microseconds
- or append a short run-local sequence number

### 3. Per-device ordering

If the same IP can be scheduled twice, writes must remain ordered. The writer-shard mapping helps, but input dedupe is still the better fix.

### 4. Schema constraints

The current schema relies partly on application-level dedupe.

For higher write concurrency, I would strongly consider adding:

- a unique constraint on `device_inventory.device_id`

I would leave `device_interfaces` and `device_neighbors` alone for the first pass unless we also redesign their merge rules.

## My Recommendation

I would implement this as:

1. `process_single_ip.py` becomes a class-backed importable pipeline returning `SingleIPScanResult`.
2. `scanner_orchestrator.py` becomes a threaded coordinator, not a subprocess launcher.
3. database writes move to dedicated writer threads, one connection each.
4. SQLite is supported with `max_db_connections=1`.
5. external databases scale by increasing writer shards and worker count independently.

That gives you the control model you asked for without breaking SQLite's single-writer reality.

## Concrete Example

### SQLite laptop run

```text
python src/scanner_orchestrator.py ^
  --targets targets.csv ^
  --keys keys.yaml ^
  --ssh-commands ssh_commands.yaml ^
  --dbconfig db-local-sqlite.yaml ^
  --max-workers-per-db-connection 20 ^
  --max-db-connections 1
```

Behavior:

- 20 IPs can be actively scanned at once
- 1 writer thread persists results serially into SQLite

### External PostgreSQL run

```text
python src/scanner_orchestrator.py ^
  --targets targets.csv ^
  --keys keys.yaml ^
  --ssh-commands ssh_commands.yaml ^
  --dbconfig db-postgresql.yaml ^
  --max-workers-per-db-connection 20 ^
  --max-db-connections 25
```

Behavior:

- up to 500 IP scan workers can be active
- 25 dedicated DB writer connections persist results in parallel

## Short Version

The cleanest solution is not "let 500 workers write carefully."

The cleanest solution is:

- many threads do network I/O
- a small, controlled number of writer threads own the DB connections
- `process_single_ip` returns structured results instead of writing inline

That design fits SQLite and external SQL backends with the same orchestration model.

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

