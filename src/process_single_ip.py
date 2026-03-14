# Copyright 2026 Benjamin Brillat
#
# Author: Benjamin Brillat
# GitHub: https://github.com/brillb
# License: Apache License 2.0
# SPDX-License-Identifier: Apache-2.0
#
# This file is part of the brillb/network-discovery-scanner project.
#
# Co-authored using AI coding assist modules in the IDE, including
# GPT, Copilot, Gemini, and similar tools.
#
# See the LICENSE file at the repository root for full license terms.

"""
Component: Single IP Processor (`process_single_ip.py`)
Recursive orchestrator for a single device. Executes Ping -> SNMP -> SSH.
"""
import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime

import module_ping
import module_portscan
import module_snmp
import module_ssh
import yaml

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from db_loader import load_database
from module_db_writer import ScanResultWriter


@dataclass(frozen=True)
class SingleIPScanRequest:
    ip: str
    keytags: tuple[str, ...] = ()


@dataclass
class ReachabilityResult:
    ping_responded: bool
    ssh_port_open: bool
    is_alive: bool


@dataclass
class SNMPResult:
    attempted: bool = False
    succeeded: bool = False
    inventory: dict = field(default_factory=dict)
    interfaces: list[dict] = field(default_factory=list)
    neighbors: list[dict] = field(default_factory=list)
    working_credential_ref: str | None = None
    error: str | None = None


@dataclass
class SSHResult:
    attempted: bool = False
    succeeded: bool = False
    working_credential_ref: str | None = None
    evidence_file_path: str | None = None
    error: str | None = None


@dataclass
class SingleIPScanResult:
    ip: str
    keytags: tuple[str, ...]
    started_at: str
    finished_at: str
    reachability: ReachabilityResult | None = None
    snmp: SNMPResult | None = None
    ssh: SSHResult | None = None
    errors: list[str] = field(default_factory=list)


def summarize_attempt_failures(phase_name, failures, default_reason):
    if not failures:
        return f"{phase_name}:{default_reason}"

    attempts = []
    for failure in failures:
        tag = failure.get("credential_ref") or failure.get("tag") or "unknown_tag"
        reason = failure.get("reason") or "unknown_error"
        detail = str(failure.get("detail") or "").strip()
        attempt_text = f"{tag}:{reason}"
        if detail:
            attempt_text = f"{attempt_text} ({detail})"
        attempts.append(attempt_text)

    return f"{phase_name}:{default_reason} [{' ; '.join(attempts)}]"


def to_relative_evidence_path(evidence_root, evidence_path):
    evidence_root_abs = os.path.abspath(evidence_root)
    evidence_path_abs = os.path.abspath(evidence_path)

    try:
        return os.path.relpath(evidence_path_abs, evidence_root_abs)
    except ValueError:
        return os.path.basename(evidence_path_abs)


def normalize_credential_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def selected_tags(request, keys_data):
    return request.keytags if request.keytags else keys_data.keys()


def build_snmp_credentials(request, keys_data):
    credentials_to_try = []

    for tag in selected_tags(request, keys_data):
        if tag not in keys_data:
            continue

        tag_data = keys_data.get(tag) or {}
        tag_index = 0

        for community in normalize_credential_list(tag_data.get("snmpv2")):
            credentials_to_try.append(
                {
                    "tag": tag,
                    "credential_ref": f"{tag}:{tag_index}",
                    "params": {"version": "2c", "community": community},
                }
            )
            tag_index += 1

        for cred in normalize_credential_list(tag_data.get("snmpv3")):
            credentials_to_try.append(
                {
                    "tag": tag,
                    "credential_ref": f"{tag}:{tag_index}",
                    "params": dict({"version": "3"}, **cred),
                }
            )
            tag_index += 1

    return credentials_to_try


def build_ssh_credentials(request, keys_data):
    credentials_to_try = []

    for tag in selected_tags(request, keys_data):
        if tag not in keys_data:
            continue

        tag_data = keys_data.get(tag) or {}

        for index, cred in enumerate(normalize_credential_list(tag_data.get("ssh_password"))):
            credentials_to_try.append(
                {
                    "tag": tag,
                    "credential_ref": f"{tag}:p{index}",
                    "params": {"username": cred["username"], "password": cred["password"]},
                }
            )

        for index, cred in enumerate(normalize_credential_list(tag_data.get("ssh_key"))):
            credentials_to_try.append(
                {
                    "tag": tag,
                    "credential_ref": f"{tag}:k{index}",
                    "params": {"username": cred["username"], "key_file": cred["key_file"]},
                }
            )

    return credentials_to_try


def evaluate_os_profile(inventory_dict, ssh_commands_data):
    """
    Evaluates SNMP responses against regex to find correct OS commands payload.
    """
    if not inventory_dict:
        return {"netmiko_device_type": "autodetect", "commands": []}

    inv = inventory_dict.get("inventory", {})
    search_string = f"{inv.get('sys_descr', '')} {inv.get('software_image', '')} {inv.get('hardware_product', '')}"

    for os_name, profile in ssh_commands_data.items():
        regex = profile.get("snmp_regex_matcher", "")
        if regex and re.search(regex, search_string, re.IGNORECASE):
            print(f"[{inv.get('hostname')}] Matched OS Profile: {os_name}")
            return profile

    return {"netmiko_device_type": "autodetect", "commands": []}


def load_yaml_file(path, label):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{label} file not found: {path}") from exc


def _utc_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class SingleIPPipeline:
    def __init__(self, *, keys_data, ssh_commands_data, evidence_dir):
        self.keys_data = keys_data or {}
        self.ssh_commands_data = ssh_commands_data or {}
        self.evidence_dir = evidence_dir

    def run(self, request: SingleIPScanRequest) -> SingleIPScanResult:
        started_at = _utc_timestamp()
        result = SingleIPScanResult(
            ip=request.ip,
            keytags=tuple(request.keytags),
            started_at=started_at,
            finished_at=started_at,
        )

        is_alive = False

        try:
            result.reachability = self._verify_reachability(request.ip)
            is_alive = result.reachability.is_alive
            if not is_alive:
                result.errors.append("reachability:unreachable")
            else:
                result.snmp = self._attempt_snmp(request)
                if result.snmp.error:
                    result.errors.append(result.snmp.error)

                os_profile = evaluate_os_profile(
                    {"inventory": result.snmp.inventory} if result.snmp and result.snmp.succeeded else None,
                    self.ssh_commands_data,
                )

                if result.reachability.ssh_port_open:
                    result.ssh = self._attempt_ssh(request, os_profile)
                else:
                    print(f"[{request.ip}] Skipping SSH because TCP/22 is closed.")
                    result.ssh = SSHResult(attempted=False, error="ssh:port_closed")

                if result.ssh and result.ssh.error:
                    result.errors.append(result.ssh.error)
        finally:
            result.finished_at = _utc_timestamp()

        return result

    def _verify_reachability(self, ip):
        print(f"[{ip}] Verifying reachability...")

        ping_res = module_ping.ping_host(ip)
        port_res = module_portscan.check_tcp_22(ip)

        ping_responded = bool(ping_res["is_alive"])
        ssh_port_open = bool(port_res["is_open"])
        is_alive = ping_responded or ssh_port_open

        if not is_alive:
            print(f"[{ip}] Unreachable.")

        return ReachabilityResult(
            ping_responded=ping_responded,
            ssh_port_open=ssh_port_open,
            is_alive=is_alive,
        )

    def _attempt_snmp(self, request):
        ip = request.ip
        print(f"[{ip}] Attempting SNMP...")

        credentials_to_try = build_snmp_credentials(request, self.keys_data)
        result = SNMPResult(attempted=True)
        failures = []

        for cred in credentials_to_try:
            res = module_snmp.get_inventory(ip, cred["params"])
            if res["status"] == "success":
                print(f"[{ip}] SNMP successful using credential: {cred['credential_ref']}")
                result.succeeded = True
                result.inventory = res["inventory"]
                result.interfaces = res.get("interfaces", [])
                result.neighbors = res.get("neighbors", [])
                result.working_credential_ref = cred["credential_ref"]
                return result

            failures.append(
                {
                    "tag": cred["tag"],
                    "credential_ref": cred["credential_ref"],
                    "reason": res.get("reason", "snmp_error"),
                    "detail": res.get("detail", ""),
                }
            )

        print(f"[{ip}] SNMP failed after trying all credentials.")
        result.error = summarize_attempt_failures("snmp", failures, "no_valid_keys")
        return result

    def _attempt_ssh(self, request, os_profile):
        ip = request.ip
        device_type = os_profile.get("netmiko_device_type", "autodetect")
        commands_to_run = os_profile.get("commands", [])
        print(f"[{ip}] Attempting SSH Phase to {device_type} ...")

        credentials_to_try = build_ssh_credentials(request, self.keys_data)
        result = SSHResult(attempted=True)
        failures = []

        for cred in credentials_to_try:
            res = module_ssh.gather_configs(
                ip,
                cred["params"],
                self.evidence_dir,
                device_type=device_type,
                commands_to_run=commands_to_run,
            )
            if res["status"] == "success":
                print(f"[{ip}] SSH successful using credential: {cred['credential_ref']}")
                result.succeeded = True
                result.working_credential_ref = cred["credential_ref"]
                result.evidence_file_path = to_relative_evidence_path(
                    self.evidence_dir,
                    res["evidence_file_path"],
                )
                return result

            failures.append(
                {
                    "tag": cred["tag"],
                    "credential_ref": cred["credential_ref"],
                    "reason": res.get("reason", "ssh_error"),
                    "detail": res.get("detail", ""),
                }
            )

        print(f"[{ip}] SSH failed.")
        result.error = summarize_attempt_failures("ssh", failures, "no_valid_keys")
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--keytags", nargs="*", default=[])
    parser.add_argument("--keys-file", required=True)
    parser.add_argument("--ssh-commands-file", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--dbconfig", required=True)

    args = parser.parse_args()

    keys_data = load_yaml_file(args.keys_file, "Keys")
    ssh_commands_data = load_yaml_file(args.ssh_commands_file, "SSH commands")

    pipeline = SingleIPPipeline(
        keys_data=keys_data,
        ssh_commands_data=ssh_commands_data,
        evidence_dir=args.evidence_dir,
    )
    request = SingleIPScanRequest(ip=args.ip, keytags=tuple(args.keytags))
    result = pipeline.run(request)

    db_handle = load_database(args.dbconfig, initialize=True)
    db_conn = db_handle.engine.connect()

    try:
        ScanResultWriter(db_conn).persist_scan_result(result)
    finally:
        db_conn.close()
        db_handle.engine.dispose()


if __name__ == "__main__":
    main()
