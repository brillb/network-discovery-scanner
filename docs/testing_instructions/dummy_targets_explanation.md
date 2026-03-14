# Dummy Targets Walkthrough

During development, we created a set of "dummy" targets to safely test the network scanner's orchestration logic without needing to authenticate against real network hardware. This allowed us to verify that the scanner correctly handles unreachable hosts, authentication failures, and database generation.

## What Was Tested

We created two files in the root directory:
1. `dummy_targets.csv`
2. `dummy_keys.yaml`

### `dummy_targets.csv`
```csv
ip_or_subnet,keytag1
127.0.0.1,dummy_credentials
```
This instructed the scanner to target `127.0.0.1` (the local laptop loopback address). It specifies that it should only try the credentials associated with the `dummy_credentials` tag.

### `dummy_keys.yaml`
```yaml
dummy_credentials:
  snmpv2:
    - "public"
  ssh_password:
    - username: "admin"
      password: "SuperSecretPassword"
```
This maps the credential tags from the CSV to specific payloads.

## Execution Flow on Localhost

When we executed `python src/scanner_orchestrator.py --targets dummy_targets.csv --keys dummy_keys.yaml --ssh-commands ssh_commands.yaml --dbconfig db.yaml`, the following pipeline occurred:

1. **Database Initialization**: The orchestrator created a new timestamped folder (e.g., `discovered_device_evidence_20260311_004438`), opened a per-run logfile in that folder, and initialized the database defined in `db.yaml` with the proper tables (`devices`, `device_inventory`, etc.).
2. **Dispatch**: The script read `127.0.0.1` and queued an in-process single-IP pipeline run for that address.
3. **Phase 1 (Reachability)**: Python executed an OS-level ping to `127.0.0.1`. The local loopback responded successfully. The database `devices` table was updated to mark `127.0.0.1` as `is_alive=True`.
4. **Phase 2 (SNMP)**: The script attempted to query `127.0.0.1` on UDP 161 using the community string `"public"`. Since the laptop does not have an SNMP daemon running, it timed out gracefully. The script logged the failure but did not crash.
5. **Phase 3 (SSH)**: Even though SNMP failed (resulting in an "autodetect" OS profile), the script proceeded to attempt SSH using the `admin/SuperSecretPassword` credentials. Since the laptop does not have an SSH server actively accepting these credentials, the Netmiko `ConnectHandler` timed out or rejected auth natively. The script handled this exception gracefully.

## Result

The database successfully recorded the single IP `127.0.0.1` as an alive host that failed to yield SNMP or SSH data. The pipeline correctly verified its error handling boundaries without crashing the orchestrator loop, proving that the tool can safely skip dead or locked-down hosts in a real-world subnet sweep.

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

