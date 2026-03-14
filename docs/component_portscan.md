# Component: Portscan (`module_portscan.py`)

## Purpose
Handles checking specific TCP/UDP ports, primarily used to record current TCP/22 reachability state for single-device scans or to sweep subnets when ICMP is blocked.

## Core Libraries
*   `python-nmap` (pip): Python wrapper for the system Nmap utility. Requires Nmap to be installed on the host laptop.
*   *Alternative*: `socket` (built-in) can be used for simple single-port TCP checks if enforcing an Nmap dependency is undesirable.

## Usage details (CLI / Environment)
While primarily imported by orchestrators, this component can run standalone for isolating firewall issues.
*   **CLI Argument**: `--ip <address>` or `--subnet <cidr>` (Required if run directly)
*   **Env Variable**: `SCANNER_PORTSCAN_TIMEOUT` (Optional, default 2 seconds)

## Interfaces (Function Calls)

`def check_tcp_22(ip_address: str, timeout: int = 2) -> dict:`
*   Uses `socket.create_connection((ip_address, 22), timeout)`.
*   **Returns**: A structured JSON-compatible dictionary.
    ```json
    {
      "ip_address": "1.2.3.4",
      "port": 22,
      "is_open": true
    }
    ```
*   **Database Impact**: `process_single_ip.py` reads this dictionary on every single-IP run and updates the `devices` table (`ssh_port_open` and `is_alive`).

`def sweep_subnet(cidr: str) -> dict:`
*   Requires `python-nmap`.
*   Executes `nmap -sn -PE -PS22 <cidr>` (Ping scan using ICMP echo and TCP SYN to port 22).
*   Parses the XML/JSON results.
*   **Returns**: A dictionary containing arrays of up/down hosts.
    ```json
    {
      "subnet": "192.168.1.0/24",
      "total_scanned": 256,
      "up_hosts": ["192.168.1.5", "192.168.1.10"],
      "down_hosts": ["192.168.1.1", "192.168.1.2"]
    }
    ```
*   **Database Impact**: The orchestrator uses the `up_hosts` array to dynamically queue new DB entries into the `devices` table before dispatching them to `process_single_ip.py`.

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

