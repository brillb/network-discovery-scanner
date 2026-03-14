# Example Walkthrough: Recursion of a Single IP (Cisco Catalyst 3750X)

## Scenario
*   **Target IP**: `1.2.3.4`
*   **Expected Device**: Cisco Catalyst 3750X
*   **CSV Input Row**: 
    `1.2.3.4,public_readonly,,standard_admin,,Cisco 3750X`
*   **Keys YAML matches**:
    *   `snmpv2.public_readonly`: "public"
    *   `ssh_passwords.standard_admin`: user "admin", pass "SuperSecretPassword"
*   **Runtime Context**: 
    `process_single_ip.py` is invoked by the orchestrator at `20260310_234500`

---

## The Execution Pipeline

### Phase 1: Reachability (`verify_reachability`)
1.  Python sub-processes the OS `ping 1.2.3.4`.
2.  Switch responds. 
3.  **Database Action**: Updates `configured discovery database -> devices`
    *   `ip_address`: '1.2.3.4'
    *   `scan_time`: '2026-03-10 23:45:00'
    *   `is_alive`: TRUE
    *   `ping_responded`: TRUE
    *   `ssh_port_open`: TRUE

### Phase 2: SNMP Inventory (`attempt_snmp`)
1.  The orchestrator passes the `public_readonly` tag. The script retrieves `"public"` from `keys.yaml`.
2.  `module_snmp.py` sends a GET request to `1.2.3.4` using community `"public"`.
3.  Switch responds with `sysDescr` containing "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)..." and `sysName` "Core-SW1".
4.  **Database Action**: Updates `configured discovery database -> device_inventory`
    *   `device_id`: (Linked to `devices` row)
    *   `hostname`: "Core-SW1"
    *   `hardware_product`: "C3750E" or vendor-specific parsed platform string (Parsed from `sysDescr`, with object ID as fallback)
    *   `software_image`: "C3750E-UNIVERSALK9-M"
    *   `software_version`: "15.2(4)"
    *   `uptime_seconds`: 864000
    *   `working_snmp_credential`: "public_readonly:0"
5.  **Database Action**: Updates `configured discovery database -> device_interfaces`
    *   Iterates the MIBs and inserts newly discovered rows for Vlan1 (1.2.3.4), GigabitEthernet1/0/1, etc.
    *   Existing interface rows for the device are retained if a later scan does not rediscover them.
6.  **Database Action**: Updates `configured discovery database -> device_neighbors`
    *   Iterates the LLDP/CDP MIBs. Switch returns info about a connected Router with IP `1.2.3.1` named `Edge-Router1`.
    *   `neighbor_hostname`: "Edge-Router1"
    *   `neighbor_ip`: "1.2.3.1"
    *   `protocol`: "CDP"
    *   Existing neighbor rows for the device are retained if a later scan does not rediscover them.
7.  Updates `devices` table: `snmp_responded` = TRUE.

### Phase 3: SSH Discovery (`attempt_ssh`)
1.  The orchestrator passes the `standard_admin` tag. The script retrieves user "admin" / pass "SuperSecretPassword" from `keys.yaml`.
2.  `module_ssh.py` uses `netmiko` to open TCP 22 and authenticate. (If this failed, it would loop the YAML file. It succeeds here.)
3.  It opens `ssh_commands.yaml`, finds the `cisco_ios` device profile array, and sequentially executes each command (e.g., `show running-config`, `show ip arp`, etc.).
4.  **Filesystem Action**: Creates the evidence trace file.
    *   Path: `discovered_device_evidence_20260310_234500/1.2.3.4-ssh-20260310_234500.txt`
    *   Contents: The raw text strings returned from the command iterations.
5.  **Database Action**: Updates `configured discovery database -> device_inventory`
    *   `working_ssh_credential`: "standard_admin:p0"
6.  **Database Action**: Updates `configured discovery database -> device_configs`
    *   `working_ssh_credential`: "standard_admin:p0"
    *   `evidence_file_path`: "discovered_device_evidence_20260310_234500/1.2.3.4-ssh-20260310_234500.txt" (stored relative to the `--evidence-dir` base path)
7.  Updates `devices` table: `ssh_responded` = TRUE.

### Completion
Pipeline terminates. The single IP is completely mapped. Control flow returns to the orchestrator to process the next IP.

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

