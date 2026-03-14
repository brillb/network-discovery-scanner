# Testing Guide for the Network Scanner

This document outlines how to test the individual components of the network scanner to ensure they are functioning correctly within your environment, as well as how to perform an end-to-end integration test.

## 1. Testing Individual Modules

Each core module was designed to be run standalone via the command line. This is incredibly useful for isolating firewall issues or verifying credentials before running a massive batch orchestration.

### Testing Ping (`module_ping.py`)
Tests basic ICMP reachability.
```bash
# Test a known good host (e.g., Google DNS or a local gateway)
python src/module_ping.py --ip 8.8.8.8
```

### Testing Portscan (`module_portscan.py`)
Tests TCP 22 fallback and Nmap subnet sweeping.
```bash
# Test a single IP for SSH port 22
python src/module_portscan.py --ip 127.0.0.1

# Test sweeping a local subnet to find alive hosts
# Note: Requires Nmap to be installed on your OS!
python src/module_portscan.py --subnet 192.168.1.0/24
```

### Testing SNMP (`module_snmp.py`)
Polls a device for system MIBs and interfaces to verify community strings or v3 encryption.
```bash
# Test SNMPv2c
python src/module_snmp.py --ip 10.0.0.1 --version 2c --community public

# Test SNMPv3
python src/module_snmp.py --ip 10.0.0.1 --version 3 --v3-user admin --v3-auth authpass --v3-priv privpass
```

### Testing SSH (`module_ssh.py`)
Verifies Netmiko can successfully connect, run commands, and save the configuration to disk.
```bash
# Test Password Auth
python src/module_ssh.py --ip 10.0.0.1 --username admin --password SuperSecret --ssh-commands-file fully_qualified_path/ssh_commands.yaml

# Test Key Auth
python src/module_ssh.py --ip 10.0.0.1 --username automation --key-file /path/to/rsa.key --ssh-commands-file fully_qualified_path/ssh_commands.yaml
```

## 2. Testing the Pipeline (`process_single_ip.py`)

To verify that the phases correctly hand off to one another (Ping -> SNMP -> SSH), you can invoke the single IP processor directly, bypassing the orchestrator's CSV logic.

```bash
# Provide absolute paths to your keys and commands files
python src/process_single_ip.py \
    --ip 10.0.0.1 \
    --keytags dummy_credentials \
    --keys-file fully_qualified_path/keys.yaml \
    --ssh-commands-file fully_qualified_path/ssh_commands.yaml \
    --evidence-dir . \
    --dbconfig fully_qualified_path/db.yaml
```
This tests database insertion natively for a single node using the backend defined in `db.yaml`.

## 3. End-to-End Orchestrator Testing

To test the entire application exactly as an architect would use it:

1. **Prepare your inputs**: Seed a run folder from `docs/sample_config_files`, then edit the copied `targets.csv`, `keys.yaml`, `ssh_commands.yaml`, and one of the DB samples copied to `db.yaml`.
2. **Execute**:
```bash
python src/scanner_orchestrator.py \
    --targets targets.csv \
    --keys keys.yaml \
    --ssh-commands ssh_commands.yaml \
    --dbconfig db.yaml \
    --evidence-dir C:\Path\To\Evidence\Folder
```

You can also validate bounded threaded concurrency:

```bash
python src/scanner_orchestrator.py \
    --targets targets.csv \
    --keys keys.yaml \
    --ssh-commands ssh_commands.yaml \
    --dbconfig db.yaml \
    --evidence-dir C:\Path\To\Evidence\Folder \
    --max-workers-per-db-connection 25 \
    --max-db-connections 1
```

For SQLite, `--max-db-connections` must remain `1`.

For external PostgreSQL, MySQL, or MariaDB backends, you can raise both settings. Example:

```bash
python src/scanner_orchestrator.py \
    --targets targets.csv \
    --keys keys.yaml \
    --ssh-commands ssh_commands.yaml \
    --dbconfig db.yaml \
    --evidence-dir C:\Path\To\Evidence\Folder \
    --max-workers-per-db-connection 20 \
    --max-db-connections 10
```

### Validation Checklist
After the orchestrator finishes:
- [ ] Check the `evidence-dir` folder. Was a new folder named `discovered_device_evidence_YYYYMMDD_HHMMSS` created?
- [ ] Inside that folder, was a per-run `logfile-YYYYMMDD_HHMMSS.txt` also created?
- [ ] Inside that folder, are there raw text files containing the device configs (e.g., `10.0.0.1-ssh-...txt`)?
- [ ] Open the database defined in `db.yaml`. Ensure the `device_inventory` and `device_interfaces` tables are fully populated with the hardware models, serial numbers, and IPs pulled from the SNMP phase.
- [ ] Confirm `device_inventory.hardware_product`, `model`, and `serial_number` resolve to useful values even on devices that primarily expose `sysObjectID` or Entity-MIB inventory data.
- [ ] Confirm `device_interfaces` contains named interfaces even when some of them have blank IPs, and that repeated scans do not create duplicate rows for the same device/interface.
- [ ] Confirm devices that only expose a standalone management IP through legacy SNMP tables still retain that address in `device_interfaces`, potentially under a synthetic `Management` interface row.
- [ ] Confirm `device_neighbors` contains readable LLDP/CDP/BGP/OSPF rows rather than malformed raw values.
- [ ] Confirm LLDP rows populate management IPs when remote devices advertise them, and BGP rows populate from both standard and Cisco-specific peer tables even when the SNMP agent returns peer addresses as raw bytes.
- [ ] Confirm `device_neighbors` retains older discoveries across subsequent scans, while duplicate rows are not reinserted.
- [ ] Confirm `device_configs.evidence_file_path` is stored relative to the `--evidence-dir` base path rather than as a machine-specific absolute path.
- [ ] Confirm `devices.last_error` is blank after a clean run and contains a readable reason string after induced reachability, SNMP, or SSH failures.
- [ ] Confirm the orchestrator honors `max-workers-per-db-connection * max-db-connections` as the active scan ceiling.
- [ ] Confirm SQLite rejects `--max-db-connections` values greater than `1`.
- [ ] Confirm overlapping CSV targets do not trigger duplicate IP scans and that the more-specific target entry wins.
- [ ] Confirm the orchestrator exits early with a readable error if `targets.csv` contains subnet sweep entries but the host laptop does not have `nmap` available on PATH.

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

