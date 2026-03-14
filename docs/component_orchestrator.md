# Component: Orchestrator (`scanner_orchestrator.py`)

## Purpose
`scanner_orchestrator.py` is the primary entry point for the scanner. It now runs the discovery workflow in-process with bounded threads instead of launching one subprocess per IP.

Its responsibilities are:

- parse CLI arguments
- initialize the database and evidence folder
- load the shared YAML inputs once
- read `targets.csv` into target rules
- resolve overlapping target precedence before scheduling work
- sweep subnets, enqueue IP scan requests, and bound memory usage with queues
- run dedicated DB writer threads so SQLite can stay on a single writer connection

## Important Terms

### `TargetSpec`

In the code, a `TargetSpec` is one normalized targeting rule loaded from one CSV row.

The name is short for "target specification". It is a rule, not a discovered device and not yet a queued worker job.

Examples:

- a row containing `192.168.1.7` becomes a single-IP `TargetSpec`
- a row containing `192.168.1.0/24` becomes a subnet `TargetSpec`

Each `TargetSpec` contains:

- the original row number
- the raw target string from the CSV
- the normalized `ipaddress` network object
- the keytags that apply if that rule wins

### `Owner` / `Owning Spec`

One IP can match multiple target rules at the same time.

Example:

- `192.168.1.0/24`
- `192.168.1.128/25`
- `192.168.1.130`

All three match `192.168.1.130`, but only one should control the actual scan.

The code calls that winning rule the "owner" or "owning spec".

Ownership means:

- this is the one CSV rule allowed to schedule that IP
- this rule's keytags are the ones used for the scan
- broader matching rules must not enqueue the same IP again

## CLI Arguments

- `--targets`: CSV file containing IPs or subnets plus optional keytags
- `--keys`: YAML credential file
- `--ssh-commands`: YAML OS-profile command mapping
- `--evidence-dir`: base path for the timestamped evidence folder
- `--dbconfig`: database backend config file
- `--max-workers-per-db-connection`: active scan workers allowed behind each DB writer connection
- `--max-db-connections`: number of dedicated DB writer connections; SQLite requires `1`

Effective maximum active scan concurrency is:

```text
max-workers-per-db-connection * max-db-connections
```

## Console UI

The orchestrator now delegates terminal presentation to
[`module_orchestrator_cli_ui.py`](../src/module_orchestrator_cli_ui.py).

That module:

- captures existing console messages
- always mirrors them to an auto-created logfile inside the run evidence folder
- renders a Blessed-based dashboard when the terminal supports it
- falls back to the plain console view when Blessed is unavailable

## Progress Logging

The orchestrator progress messages separate pipeline state into distinct counters:

- `running`
  - IP pipelines currently executing in scan worker threads
- `queued`
  - IP pipelines accepted for scanning but not yet picked up by a worker
- `awaiting_db`
  - scans finished on the network side and waiting to be persisted by a writer thread
- `submitted`
  - total IP pipelines queued during the run
- `completed`
  - total IP pipelines fully persisted

This means values such as `queued=31` no longer imply 31 active worker threads. Active scan concurrency is represented only by `running=<n>/<max>`.

## Thread Model

The orchestrator uses three layers:

1. Main thread
   - parses inputs
   - loads target rules
   - sweeps subnets
   - enqueues IP scan requests
2. Scan worker threads
   - run `SingleIPPipeline.run()` for one IP at a time
   - perform network I/O only
   - never write directly to the database
3. Writer threads
   - one thread per DB connection
   - own the database connections
   - persist completed scan results

This separation is what allows SQLite to support concurrent scanning safely: many workers can scan while one writer thread serializes the DB updates.

## Target Precedence Rules

Targets are resolved as rules, not expanded into one giant in-memory IP list.

For any candidate IP:

- the most specific matching target wins
- a direct IP wins over a containing subnet
- a longer prefix wins over a shorter prefix
- if two rules have the same prefix length, the later CSV row wins

Examples:

- `192.168.1.7` overrides `192.168.1.0/24`
- `192.168.1.128/25` overrides `192.168.1.0/24` for `192.168.1.128-255`
- duplicate identical targets are de-duplicated, with the later CSV row taking precedence

The orchestrator also keeps a per-run set of already scheduled IPs so an address is scanned at most once.

## How `TargetPlanner` Works

`TargetPlanner` is the rule-resolution helper inside the orchestrator.

Its job is to answer two questions:

1. Which `TargetSpec` owns a given IP?
2. Should the current rule be allowed to schedule this IP?

It keeps three key structures:

- `specs`
  - the full list of normalized CSV rules
- `specs_by_version`
  - the same rules split into IPv4 and IPv6 groups
- `latest_identical_row`
  - a lookup used to ignore exact duplicate rows when a later identical row exists

### `owning_spec_for_ip(ip)`

This function evaluates all matching rules for an IP and returns the winner.

Winning logic:

- the rule must contain the IP
- the longest prefix wins
- if prefix lengths tie, the later CSV row wins

### `should_process_spec_ip(spec, ip)`

This asks:

"Is this specific rule the owner of this IP?"

If yes, the IP may be scheduled.

If no, the IP is skipped because some other more-specific or later rule owns it.

### `is_shadowed_identical_network(spec)`

This handles exact duplicate rules.

Example:

- row 5: `192.168.1.0/24`
- row 9: `192.168.1.0/24`

Row 5 is shadowed, so only row 9 survives.

## Large-Range Behavior

The orchestrator does not preload all possible IPs from a large subnet such as `192.168.0.0/16`.

Memory is bounded by:

- the target rule list from CSV
- the bounded scan work queue
- the bounded DB result queues
- the set of already scheduled IPs

Subnet discovery still depends on `module_portscan.sweep_subnet()` returning active hosts, but the orchestrator no longer builds a full expanded IP plan in memory.

## Rule-To-Job Flow

The orchestrator moves through three layers:

1. CSV rows
   - raw user input
2. `TargetSpec` objects
   - normalized targeting rules
3. single-IP scan requests
   - concrete worker jobs for one IP

That distinction matters because a subnet `TargetSpec` is not itself a queued scan. It is only a rule that may produce many concrete single-IP jobs after the subnet sweep returns active hosts.

For each candidate IP produced by a subnet sweep:

1. the planner checks who owns the IP
2. only the owning rule may schedule it
3. the run-state tracker ensures it is queued once

## High-Level Flow

1. Parse CLI and validate DB concurrency rules.
2. Initialize the schema and create the evidence folder.
3. Load `keys.yaml` and `ssh_commands.yaml` once.
4. Read `targets.csv` into `TargetSpec` rules.
5. Start scan worker threads and DB writer threads.
6. Walk the target rules:
   - direct IPs are scheduled if they win precedence
   - subnets are swept and only winning IPs are scheduled
7. Scan workers run the single-IP pipeline and push results to the appropriate writer shard.
8. Writer threads persist the results and commit once per IP.
9. The orchestrator waits for the queues to drain and then exits with any runtime failures summarized.

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

