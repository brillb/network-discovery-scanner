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
Component: Portscan
Handles checking specific TCP ports, primarily used for direct SSH reachability
state checks or subnet sweeps.
"""
import socket
import nmap
import argparse
import os
import json
import ipaddress
from datetime import datetime


def ensure_nmap_available() -> None:
    """
    Validate that the system `nmap` executable is available to python-nmap.

    Raises:
        RuntimeError: if python-nmap cannot locate or start the `nmap` binary.
    """
    try:
        nmap.PortScanner()
    except (nmap.PortScannerError, OSError) as exc:
        raise RuntimeError(
            "the system `nmap` executable is not available on PATH"
        ) from exc

def check_tcp_port(ip_address: str, port: int = 22, timeout: int = None) -> dict:
    """
    Checks if a TCP port is open on the target using standard sockets.
    
    Args:
        ip_address (str): The target IP address.
        port (int): TCP port to probe. Defaults to 22.
        timeout (int): Timeout in seconds. Defaults to env var SCANNER_PORTSCAN_TIMEOUT or 2.
    
    Returns:
        dict: A JSON-compatible dictionary with open status.
    """
    if timeout is None:
        timeout = int(os.environ.get("SCANNER_PORTSCAN_TIMEOUT", 2))
        
    is_open = False
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            is_open = True
    except (socket.timeout, ConnectionRefusedError, OSError):
        is_open = False

    return {
        "ip_address": ip_address,
        "port": port,
        "is_open": is_open
    }


def check_tcp_22(ip_address: str, timeout: int = None) -> dict:
    """
    Backward-compatible wrapper for the default SSH port.
    """
    return check_tcp_port(ip_address, port=22, timeout=timeout)

def sweep_subnet(cidr: str) -> dict:
    """
    Uses python-nmap to sweep a subnet and discover active hosts.
    Executes an ICMP echo and TCP SYN to port 22 scan.
    
    Args:
        cidr (str): Subnet in CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        dict: A dictionary containing arrays of up/down hosts.
    """
    # Validate CIDR
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return {"error": f"Invalid CIDR notation: {e}"}

    try:
        nm = nmap.PortScanner()
    except (nmap.PortScannerError, OSError) as exc:
        return {"error": f"Unable to run nmap for subnet sweep: {exc}"}
    
    # -sn : Ping Scan - disable port scan
    # -PE : ICMP echo discovery
    # -PS22 : TCP SYN discovery on port 22
    scan_args = "-sn -PE -PS22"
    
    nm.scan(hosts=cidr, arguments=scan_args)
    
    up_hosts = []
    down_hosts = []
    
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            up_hosts.append(host)
        else:
            down_hosts.append(host)
            
    # Calculate total logically based on the network size vs responders
    total_hosts_in_subnet = network.num_addresses
            
    # nmap only reports on hosts it processed or found up depending on privileges/args,
    # down hosts might not be enumerated in all_hosts() if -sn completely fails to see them.
    # However we return what nmap saw.
    
    return {
        "subnet": cidr,
        "total_scanned_or_implied": total_hosts_in_subnet,
        "up_hosts": up_hosts,
        "down_hosts": down_hosts
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone Portscan Component")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="IP address to check a TCP port")
    group.add_argument("--subnet", help="Subnet CIDR to sweep")
    parser.add_argument("--port", type=int, default=22, help="TCP port to check with --ip (default: 22)")
    
    args = parser.parse_args()
    
    if args.ip:
        result = check_tcp_port(args.ip, port=args.port)
        print(json.dumps(result, indent=2))
    elif args.subnet:
        result = sweep_subnet(args.subnet)
        print(json.dumps(result, indent=2))
