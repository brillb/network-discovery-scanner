# Component: SSH (`module_ssh.py`)

## Purpose
This module handles remote CLI interactions. It requires a high degree of privileges and focuses on deep-dive configuration backups.

## Core Libraries
*   `netmiko`: The industry standard for network device SSH automation handling varied prompts, paging, and vendor idiosyncrasies.
*   `yaml`: Parses the mapping definitions connecting `device_type` logic to specific terminal commands.

## Usage details (CLI / Environment)
While designed to be imported, this script can be run standalone to quickly backup a single device or troubleshoot auth.
*   **CLI Arguments**: 
    *   `--ip <address>` (Required)
    *   `--username <string>` (Required)
    *   `--password <string>`, `--key-file <path>` (Need at least one)
    *   `--port <integer>` (Optional, defaults to `22`)
    *   `--evidence-dir <path>` (Optional, defaults to current directory)
    *   `--device-type <netmiko_type>` (Optional, e.g. `cisco_ios`)
*   **Env Variables**: `SCANNER_SSH_TIMEOUT`

## Interfaces (Function Calls)

`def gather_configs(ip_address: str, ssh_params: dict, evidence_dir: str, device_type: str = 'autodetect', ssh_commands_file_path: str = None) -> dict:`
*   **Input**: `ssh_params` contains usernames, passwords, key-file paths, and an optional per-credential SSH `port` from the YAML lookup. `evidence_dir` dictates where the raw traceback is saved. `device_type` helps Netmiko connect faster if known from the SNMP phase. `ssh_commands_file_path` brings the OS-defined arrays into execution.
*   **Logic**:
    *   Performs a lightweight SSH banner probe on the credential's configured port before invoking Netmiko so non-SSH listeners and immediately-closing sockets fail cleanly.
    *   Finds matching YAML configuration for `device_type`.
    *   Attempts `ConnectHandler(**ssh_params)`, including the configured TCP port.
    *   Disables terminal paging.
    *   Loops sequentially over each string in the array. Saves string exactly as received directly to `<evidence_dir>/<ip_address>-ssh-<YYYYMMDD_HHMMSS>.txt`.
*   **Returns**: A structured JSON-compatible dictionary:
    ```json
    {
      "status": "success",
      "evidence_file_path": "/absolute/path/to/evidence_dir/1.2.3.4-ssh-20260310_234500.txt"
    }
    ```
    *(Returns `{"status": "error", "reason": "auth_failure"}` on failure)*
*   **Database & Filesystem Impact**:
    *   **Filesystem**: This module natively writes the execution outputs to the disk in the provided `evidence_dir`.
    *   **Database**: The calling orchestrator processes this JSON return. Before logging into `device_configs`, it converts `evidence_file_path` to a path relative to the `--evidence-dir` argument so scan results remain portable across different computers.
    *   **Credential Recording Model**: The orchestrator intentionally stores the successful SSH credential reference in two places. `device_inventory.working_ssh_credential` holds the latest successful SSH credential for the device summary row, while `device_configs.working_ssh_credential` stores the credential reference used for that specific evidence snapshot. This duplication is intentional so browsers and reports can read the latest credential from inventory while still preserving per-evidence history.

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

