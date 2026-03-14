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
Component: SSH
Handles remote CLI interactions, gathering configuration and topology data.
"""
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import argparse
import os
import json
import socket
from datetime import datetime


def _normalize_port(port_value) -> int:
    if port_value in (None, ""):
        return 22

    port = int(port_value)
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid SSH port: {port}")
    return port


def _probe_ssh_banner(ip_address: str, port: int, timeout: int) -> tuple[bool, str | None]:
    """
    Confirm the target TCP port is speaking SSH before Netmiko/Paramiko takes over.
    """
    max_lines = 5
    max_bytes = 1024

    try:
        with socket.create_connection((ip_address, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            buffer = b""
            lines_seen = 0

            while len(buffer) < max_bytes and lines_seen < max_lines:
                chunk = sock.recv(256)
                if not chunk:
                    break

                buffer += chunk
                while b"\n" in buffer:
                    raw_line, _, remainder = buffer.partition(b"\n")
                    buffer = remainder
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    lines_seen += 1

                    if line.startswith("SSH-"):
                        return True, None

                    if lines_seen >= max_lines:
                        return False, f"non_ssh_banner:{line[:120]}"

            if buffer:
                trailing_line = buffer.decode("utf-8", errors="replace").strip()
                if trailing_line.startswith("SSH-"):
                    return True, None
                if trailing_line:
                    return False, f"non_ssh_banner:{trailing_line[:120]}"

            return False, "banner_missing_or_connection_closed"
    except socket.timeout:
        return False, "banner_timeout"
    except ConnectionRefusedError:
        return False, "connection_refused"
    except OSError as exc:
        return False, f"socket_error:{exc}"

def gather_configs(
    ip_address: str,
    ssh_params: dict,
    evidence_dir: str,
    device_type: str = 'autodetect',
    ssh_commands_file_path: str = None,
    commands_to_run: list[str] | None = None,
) -> dict:
    """
    Connects to the device via SSH, and executes a mapped list of commands.
    
    Args:
        ip_address (str): Target IP.
        ssh_params (dict): Contains 'username', 'password' or 'key_file'.
        evidence_dir (str): Directory to save raw config trace.
        device_type (str): Netmiko device type.
        ssh_commands_file_path (str): Path to ssh_commands.yaml
        
    Returns:
        dict: A dictionary containing the file path for gathered evidence.
    """
    
    # Load yaml map
    commands = list(commands_to_run or ["show running-config"])
    if commands_to_run is None and ssh_commands_file_path and os.path.exists(ssh_commands_file_path):
        import yaml
        try:
            with open(ssh_commands_file_path, "r") as f:
                commands_yml = yaml.safe_load(f)
                
            for profile_key, profile_data in commands_yml.items():
                if profile_data.get('netmiko_device_type') == device_type:
                    commands = profile_data.get('commands', [])
                    break
        except Exception as e:
            print(f"Error loading ssh_commands_file: {e}")
            pass
            
    # Setup connection dict
    try:
        port = _normalize_port(ssh_params.get("port", 22))
    except (TypeError, ValueError) as exc:
        return {
            "status": "error",
            "reason": "invalid_port",
            "detail": str(exc),
        }
    connection_params = {
        'ip': ip_address,
        'port': port,
        'username': ssh_params.get('username'),
        'device_type': device_type,
        'global_delay_factor': 2,
    }
    
    timeout = int(os.environ.get("SCANNER_SSH_TIMEOUT", 15))
    connection_params['timeout'] = timeout
    connection_params['banner_timeout'] = timeout
    connection_params['auth_timeout'] = timeout
    connection_params['session_timeout'] = timeout
    
    if 'password' in ssh_params and ssh_params['password']:
        connection_params['password'] = ssh_params['password']
    if 'key_file' in ssh_params and ssh_params['key_file']:
        connection_params['key_file'] = ssh_params['key_file']
        connection_params['use_keys'] = True

    banner_ok, banner_detail = _probe_ssh_banner(ip_address, port, timeout)
    if not banner_ok:
        return {
            "status": "error",
            "reason": "ssh_banner_error",
            "detail": banner_detail,
        }

    try:
        with ConnectHandler(**connection_params) as net_connect:
            net_connect.enable()
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = f"{ip_address}-ssh-{timestamp}.txt"
            filepath = os.path.join(evidence_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                for run_cmd in commands:
                    try:
                        cmd_output = net_connect.send_command(run_cmd)
                        f.write(f"=== {run_cmd} ===\n")
                        f.write(cmd_output)
                        f.write("\n\n")
                    except Exception as e:
                        f.write(f"=== {run_cmd} (FAILED) ===\n{str(e)}\n\n")

            return {
                "status": "success",
                "evidence_file_path": filepath
            }
            
    except NetmikoAuthenticationException:
        return {"status": "error", "reason": "auth_failure"}
    except NetmikoTimeoutException:
        return {"status": "error", "reason": "timeout"}
    except Exception as e:
        return {
            "status": "error",
            "reason": "ssh_exception",
            "detail": str(e),
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone SSH Component")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--key-file")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--device-type", default="autodetect")
    parser.add_argument("--evidence-dir", default=os.getcwd())
    parser.add_argument("--ssh-commands-file")
    
    args = parser.parse_args()
    
    params = {"username": args.username}
    params["port"] = args.port
    if args.password:
        params["password"] = args.password
    if args.key_file:
        params["key_file"] = args.key_file
        
    res = gather_configs(args.ip, params, args.evidence_dir, args.device_type, args.ssh_commands_file)
    print(json.dumps(res, indent=2))
