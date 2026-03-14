# `scanner_orchestrator.py` Parallelism Explained

## Summary

The orchestrator now uses threaded in-process parallelism instead of one subprocess per IP.

There are two separate concurrency controls:

- scan worker concurrency
- DB writer concurrency

Configured by:

- `--max-workers-per-db-connection`
- `--max-db-connections`

Total scan worker count is:

```text
max-workers-per-db-connection * max-db-connections
```

## Why The Split Matters

Network discovery work is mostly I/O bound.

Database writes are constrained by the backend:

- SQLite should use one writer connection
- external SQL backends can use multiple writer connections

If scan workers wrote directly to the DB, SQLite would force the whole scanner into effective serial behavior. By separating workers from writers, the scanner can run many network scans in parallel while still respecting the DB write limits.

## Execution Layers

### 1. Main thread

- parse CLI
- initialize DB and evidence folder
- load YAML once
- read target rules
- sweep subnets
- enqueue scan work

### 2. Scan worker threads

- dequeue one `SingleIPScanRequest`
- run `SingleIPPipeline`
- produce a `SingleIPScanResult`
- enqueue the result to the correct writer shard

### 3. Writer threads

- own one DB connection each
- dequeue completed results
- persist them through `ScanResultWriter`
- commit once per IP

## Queue Backpressure

The orchestrator uses bounded queues so large scans do not create an unbounded in-memory backlog.

That matters for large inputs such as `/16` ranges:

- the main thread blocks when scan workers are saturated
- scan workers block when writer queues are saturated
- memory remains bounded by queue sizes instead of by total possible targets

Runtime log counters reflect those stages directly:

- `running`: currently executing scan workers
- `queued`: requests waiting in the scan queue
- `awaiting_db`: completed scans waiting for a writer thread

When the Blessed dashboard is active, those same counters are shown in the
status bars while the traditional progress messages continue in the middle log
pane. If Blessed falls back on Windows or in a non-TTY shell, the same messages
still go to the plain console and to the per-run logfile in the evidence
folder.

## Target Overlap Handling

Before scheduling, the orchestrator resolves overlapping target rules:

- more specific rules win
- direct IPs beat subnets
- longer prefixes beat shorter prefixes
- ties go to the later CSV row

This prevents duplicate full scans of the same IP even when the CSV mixes broad and specific targets.

## SQLite Example

```text
--max-workers-per-db-connection 20
--max-db-connections 1
```

Behavior:

- 20 IP scans may run concurrently
- 1 writer thread serializes all DB commits

## External SQL Example

```text
--max-workers-per-db-connection 20
--max-db-connections 25
```

Behavior:

- up to 500 IP scans may run concurrently
- 25 writer threads persist results in parallel

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

