# Component: Single IP Processor (`process_single_ip.py`)

## Purpose
`process_single_ip.py` now has two roles:

1. provide the importable `SingleIPPipeline` used by the threaded orchestrator
2. preserve the standalone CLI wrapper for running one IP end-to-end

The important architectural change is that the pipeline performs network discovery and returns a structured result object. It no longer owns the database write transaction during normal orchestrator execution.

## Main Types

- `SingleIPScanRequest`
  - input for one target IP plus resolved keytags
- `SingleIPScanResult`
  - finished scan payload for one IP
- `ReachabilityResult`
- `SNMPResult`
- `SSHResult`
- `SingleIPPipeline`
  - class that runs the discovery phases and builds the result

## Pipeline Flow

`SingleIPPipeline.run()` executes:

1. reachability
2. SNMP
3. OS profile evaluation
4. SSH, but only when TCP/22 was confirmed open during reachability
5. result finalization

The returned result contains:

- timestamps
- reachability state
- SNMP success/failure plus inventory/interfaces/neighbors
- SSH success/failure plus evidence path
- final summarized errors

## What It Does Not Do

Inside the threaded orchestrator, the pipeline does not:

- open a database connection
- commit per phase
- write directly to tables

That work is handled later by the writer thread through `ScanResultWriter`.

## CLI Wrapper

The standalone CLI still supports:

- `--ip`
- `--keytags`
- `--keys-file`
- `--ssh-commands-file`
- `--evidence-dir`
- `--dbconfig`

When used directly, the wrapper:

1. loads YAML files
2. runs `SingleIPPipeline`
3. persists the returned result with `ScanResultWriter`

## Credential Selection

Credential behavior is unchanged:

- if `--keytags` are provided, only those tags are attempted
- otherwise all configured tags are candidates
- SNMP and SSH credentials are tried sequentially until one succeeds

## SSH Command Mapping

The pipeline now loads `ssh_commands.yaml` once per orchestrator run and passes the selected command list directly to `module_ssh.py`.

That removes repeated YAML file reads from every SSH credential attempt in every worker.

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

