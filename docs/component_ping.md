# Component: Ping (`module_ping.py`)

## Purpose
A narrow-focused module handling ICMP echo requests to determine basic layer-3 reachability.

## Core Libraries
*   `subprocess`: To execute system `ping` command (varies by OS, but highly reliable).
    *   *Alternative*: `ping3` library from pip (requires root/admin privileges which might not be viable for standard users, hence OS `subprocess` is often safer for a cross-platform laptop script).

## Usage details (CLI / Environment)
While primarily imported by `process_single_ip.py`, this module can run standalone for debugging.
*   **CLI Argument**: `--ip <address>` (Required if run directly)
*   **Env Variable**: `SCANNER_PING_TIMEOUT` (Optional, default 2 seconds)

## Interfaces (Function Calls)

`def ping_host(ip_address: str, timeout: int = 2) -> dict:`
*   Executes `ping -n 1 -w <timeout>` (Windows) or `ping -c 1 -W <timeout>` (Linux/macOS).
*   Parses the exit code and stdout.
*   **Returns**: A structured JSON-compatible dictionary.
    ```json
    {
      "ip_address": "1.2.3.4",
      "timestamp": "2026-03-10T23:45:00",
      "is_alive": true,
      "response_time_ms": 14 
    }
    ```
*   **Database Impact**: The calling module (`process_single_ip`) takes this dictionary and directly updates the `devices` table (specifically the `is_alive` and `ping_responded` boolean columns, and logs the `scan_time`).

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

