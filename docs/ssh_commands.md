# SSH Commands File Guide (`ssh_commands.yaml`)

## Purpose
[`ssh_commands.yaml`](../src/ssh_commands.yaml) defines which CLI commands the scanner should run after a successful SSH login.

It is the bridge between:

- the SNMP-based platform identification done in [`process_single_ip.py`](../src/process_single_ip.py)
- the Netmiko SSH session created in [`module_ssh.py`](../src/module_ssh.py)

In practice, this file tells the scanner:

- how to recognize a device platform from SNMP strings
- which Netmiko `device_type` to use
- which commands to execute and save as evidence

## Where The Sample Lives

The current sample file is here:

- [`src/ssh_commands.yaml`](../src/ssh_commands.yaml)

You can copy that file into a client or project folder and customize it per environment.

## File Structure

The file is a YAML mapping. Each top-level key is an OS or platform profile.

Each profile contains:

- `snmp_regex_matcher`
- `netmiko_device_type`
- `commands`

Example:

```yaml
cisco_ios:
  snmp_regex_matcher: "(?i)(IOS Software|Cisco IOS-XE|Cisco IOS XE)"
  netmiko_device_type: "cisco_ios"
  commands:
    - "show running-config"
    - "show cdp neighbors detail"
    - "show lldp neighbors detail"
    - "show version"
```

## Field Reference

### Top-level profile name
This is just a label for the profile, such as:

- `cisco_ios`
- `juniper_junos`
- `paloalto_panos`

The profile name is not sent to the device directly. It is only used as an internal identifier in the YAML structure.

### `snmp_regex_matcher`
This is a regular expression used by [`process_single_ip.py`](../src/process_single_ip.py) to decide which SSH profile applies to the device.

The regex is evaluated against a combined search string built from SNMP-discovered values, primarily:

- `sys_descr`
- `software_image`
- `hardware_product`

Important behavior:

- the first matching profile wins
- matching is done in the YAML iteration order
- broad regexes placed too early can accidentally catch devices intended for a more specific profile

Because of that, keep specific profiles above generic ones when there is overlap.

### `netmiko_device_type`
This is the Netmiko platform type passed into the SSH module.

Examples from the sample file:

- `cisco_ios`
- `cisco_nxos`
- `cisco_xr`
- `juniper_junos`
- `paloalto_panos`
- `hp_procurve`
- `linux` for some CLI fallback cases

This value must be a valid Netmiko device type for your installed Netmiko version.

### `commands`
This is the ordered list of commands the scanner will execute after login.

Behavior:

- commands are executed sequentially
- output is written to the evidence file in the same order
- if a command fails, the scanner records the failure in the evidence file and continues with the next command

Example evidence section format:

```text
=== show version ===
<device output>

=== show ip arp ===
<device output>
```

## How Matching Works

The flow is:

1. SNMP inventory is collected.
2. [`process_single_ip.py`](../src/process_single_ip.py) builds a search string from the SNMP inventory fields.
3. It walks the profiles in `ssh_commands.yaml` from top to bottom.
4. The first profile whose `snmp_regex_matcher` matches is selected.
5. Its `netmiko_device_type` and `commands` are passed to [`module_ssh.py`](../src/module_ssh.py).

If no profile matches, the processor falls back to:

- `netmiko_device_type: autodetect`
- `commands: []`

Then inside [`module_ssh.py`](../src/module_ssh.py), if no matching command set is found for the selected `device_type`, it falls back to:

```python
["show running-config"]
```

So the system has two fallback layers:

- profile selection fallback in `process_single_ip.py`
- command list fallback in `module_ssh.py`

## How To Use It

### During normal scanner runs
Pass the file to the orchestrator with `--ssh-commands`.

Example:

```bash
python src/scanner_orchestrator.py \
    --targets XYZcorp_scanning/targets.csv \
    --keys XYZcorp_scanning/keys.yaml \
    --ssh-commands XYZcorp_scanning/ssh_commands.yaml \
    --dbconfig XYZcorp_scanning/db.yaml \
    --evidence-dir XYZcorp_scanning/scan_results
```

### Recommended project layout
For real use, keep a client-specific copy rather than editing the shared sample in `src/`.

Example:

```text
XYZcorp_scanning/
  targets.csv
  keys.yaml
  ssh_commands.yaml
  db.yaml
  scan_results/
```

## How To Add A New Platform

Add a new top-level profile with:

- a specific regex that matches that platform reliably
- the correct Netmiko device type
- a command list that is safe and useful

Example:

```yaml
fortinet_fortios:
  snmp_regex_matcher: "(?i)(Fortinet|FortiGate|FortiOS)"
  netmiko_device_type: "fortinet"
  commands:
    - "show full-configuration"
    - "get system status"
    - "get router info routing-table all"
    - "get system arp"
```

## Editing Guidance

### Prefer safe read-only commands
This file should contain operational show-style commands, not configuration-changing commands.

Good examples:

- `show running-config`
- `show version`
- `show arp`
- `show route`
- `show interfaces terse`

Avoid:

- `reload`
- `write erase`
- `configure`
- `delete`
- any interactive or destructive command

### Order commands intentionally
Put the most important commands first so partial evidence is still useful if later commands fail.

Typical order:

1. configuration
2. version and system identity
3. interfaces
4. ARP and MAC tables
5. neighbor detail
6. routing detail

### Keep regexes narrow when possible
A regex like `(?i)(Cisco)` is usually too broad if you need different behavior for IOS, NX-OS, XR, ASA, or FTD.

Prefer more specific patterns such as:

- `(?i)(IOS-XR|Cisco IOS XR)`
- `(?i)(NX-OS|Nexus)`
- `(?i)(Cisco ASA|Adaptive Security Appliance|ASAv)`

## Current Sample Profiles

The sample file currently includes profiles for:

- Cisco IOS and IOS-XE
- Cisco NX-OS
- Cisco IOS-XR
- Juniper Junos
- Palo Alto PAN-OS
- F5 TMOS
- Cisco FTD
- Cisco ASA
- Aruba OS
- Aruba SD-WAN / Silver Peak
- HP ProCurve
- Cisco Meraki
- Citrix NetScaler

Use these as starting points, not as guaranteed production-ready command sets for every environment.

## Operational Notes

- The scanner does not validate the command list before login; invalid commands fail at runtime and their failure text is written into the evidence file.
- The evidence file path is stored in the database relative to `--evidence-dir` when possible.
- SSH credential tracking is separate from command selection. Credentials come from `keys.yaml`, while command selection comes from `ssh_commands.yaml`.
- Successful SSH runs update both `device_inventory.working_ssh_credential` and `device_configs.working_ssh_credential` for their respective summary and evidence-history use cases.

## Related Files

- [`src/ssh_commands.yaml`](../src/ssh_commands.yaml)
- [`module_ssh.py`](../src/module_ssh.py)
- [`process_single_ip.py`](../src/process_single_ip.py)
- [`component_ssh.md`](component_ssh.md)
- [`GETTING_STARTED.md`](../GETTING_STARTED.md)

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

