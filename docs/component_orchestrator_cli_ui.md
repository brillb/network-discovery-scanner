# Component: Orchestrator CLI UI (`module_orchestrator_cli_ui.py`)

## Purpose
This module keeps terminal presentation concerns out of `scanner_orchestrator.py`.

It is responsible for:

- mirroring console output to a per-run logfile
- capturing existing `print()` output from all scanner threads
- rendering an optional Blessed-based dashboard when the terminal supports it
- tracking live orchestrator status for the top and bottom bars

## Main Interfaces

- `build_default_logfile_path(evidence_dir)`
  - builds the per-run logfile path inside the evidence folder
- `OrchestratorCliUI`
  - context manager that activates output capture and the optional dashboard

## Logfile Behavior

Each orchestrator run now gets a logfile automatically inside that run's
timestamped evidence folder:

- `logfile-<YYYYMMDD_HHMMSS>.txt`

Behavior:

- ANSI color codes are stripped before writing to the logfile
- messages from worker threads, writer threads, and the main thread all flow to
  the same file
- the logfile is opened once near startup and flushed as messages arrive

## Dashboard Layout

When `blessed` is available and stdout is attached to an interactive terminal,
the module renders three areas:

1. top status bar
   - DB summary
   - elapsed runtime
   - active worker count
   - target-rule progress
   - submitted/completed/failure counters
2. middle log pane
   - the live progress messages already emitted by the scanner
3. bottom status bar
   - scan queue depth
   - writer queue depth
   - last DB write target
   - current target rule
   - logfile and evidence paths

## Runtime Status Inputs

The orchestrator feeds the module structured state updates for:

- running scan workers
- queued scan jobs
- scans awaiting DB persistence
- submitted/completed totals
- runtime failure count
- target rule progress
- task queue depth
- per-writer queue depths
- last DB write target

The existing scanner messages still come from normal `print()` calls. The UI
captures those prints instead of asking every module to render its own screen.

## Windows Note

The dashboard now uses `blessed`, which has current cross-platform support
including Windows terminals. The requirements file now includes:

- `blessed`

If `blessed` is unavailable or stdout is not a TTY, the scanner falls back to the
plain console view while still writing the auto-created logfile.

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

