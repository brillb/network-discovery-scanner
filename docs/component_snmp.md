# Component: SNMP (`module_snmp.py`)

## Purpose
This module handles all SNMP polling (v2c and v3). It is responsible for gathering baseline inventory, health metrics, and L2/L3 topology (Neighbors) without requiring CLI access.

## Core Libraries
*   `pysnmp` or `easysnmp`. (We recommend `pysnmp` (high-level API `pysnmp.hlapi`) natively as it does not strictly require system-level C-bindings to be compiled, making laptop distribution easier).

## Usage details (CLI / Environment)
While primarily invoked by `process_single_ip.py`, it can be tested standalone:
*   **CLI Arguments**: 
    *   `--ip <address>` (Required)
    *   `--version <2c|3>` (Required)
    *   `--community <string>` (Required for v2c)
    *   `--v3-user`, `--v3-auth`, `--v3-priv` etc. (Required for v3)
*   **Env Variables**: `SCANNER_SNMP_TIMEOUT`, `SCANNER_SNMP_RETRIES`

## Interfaces (Function Calls)

`def get_inventory(ip_address: str, snmp_params: dict) -> dict:`
*   **Input**: `snmp_params` contains dictionaries with either `{ 'version': '2c', 'community': '...' }` or v3 authentication properties. 
*   **Logic**:
    *   Creates an SNMP engine and attempts a baseline GET against standard system OIDs (`sysDescr`, `sysObjectID`, `sysUpTime`, `sysName`) to validate authentication and collect identity data.
    *   Parses `sysDescr` into usable inventory fields such as `hardware_product`, `model`, `software_image`, and `software_version`, while retaining raw description context in `sys_descr` for downstream OS profiling.
    *   Uses vendor and Entity-MIB fallbacks when `sysDescr` is insufficient, including `entPhysicalModelName`, `entPhysicalSerialNum`, and selected `sysObjectID` mappings for platforms such as virtual Cisco routers.
    *   Walks both legacy IPv4 interface tables (`ipAdEntAddr`, `ipAdEntIfIndex`, `ifDescr`) and the newer `ipAddressTable` / `ifName` views to map interface addresses back to real interface names.
    *   Decodes certain legacy SNMP values from their raw byte representation rather than trusting the default string conversion. This is important for agents that return IPv4 data as octets in values such as `ipAdEntAddr`, `ipAdEntNetMask`, and `bgpPeerRemoteAddr`.
    *   Includes named interfaces even when they have no routed IP address, so switchports and Layer 2 interfaces still appear in inventory.
    *   If a device only exposes a standalone management IP in the legacy address table and no reliable per-interface IP mapping, the module records that address as a synthetic `Management` interface rather than dropping it.
    *   Walks LLDP, CDP, BGP, and OSPF neighbor tables. For LLDP it correlates chassis ID, system name, and management address tables. For BGP it checks both standard BGP4-MIB and Cisco `cbgpPeer2` tables, decoding peer addresses from raw values when needed.
*   **Returns**: A structured JSON-compatible dictionary containing both inventory and interfaces:
    ```json
    {
      "status": "success",
      "inventory": {
        "hostname": "Core-SW1",
        "hardware_product": "Catalyst 3750X",
        "model": "C3750E",
        "software_image": "C3750E-UNIVERSALK9-M",
        "software_version": "15.2(4)",
        "serial_number": "FOC1234ABCD",
        "uptime_seconds": 864000,
        "power_status": "Unknown",
        "sys_descr": "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)..."
      },
      "interfaces": [
        {"name": "Vlan1", "ip": "1.2.3.4", "mask": "255.255.255.0"},
        {"name": "GigabitEthernet1/0/1", "ip": "", "mask": ""}
      ],
      "neighbors": [
        {
          "neighbor_hostname": "Edge-Router1",
          "neighbor_ip": "1.2.3.1",
          "local_port": "Unknown",
          "remote_port": "Unknown",
          "protocol": "CDP"
        }
      ]
    }
    ```
    *(Returns structured errors such as `{"status": "error", "reason": "no_snmp_response", "detail": "No SNMP response received before timeout"}` or `{"status": "error", "reason": "no_valid_keys", ...}` when the SNMP engine reports a security or authorization failure.)*
*   **Database Impact**: The calling module persists this dictionary. The `inventory` object upserts the `device_inventory` table for the device, including `serial_number` when the agent exposes it. Neighbor rows remain append-only with deduplication. Interface rows are treated as one logical row per `device_id + interface_name`: repeat scans do not create duplicates, and later scans only fill in missing IP or mask data when they have better information. In cases where only a standalone management address is discoverable, that row may be written under the synthetic interface name `Management`.

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

