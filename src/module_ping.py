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
Component: Ping
Handles ICMP echo requests to determine basic layer-3 reachability.
"""
import subprocess
import platform
import argparse
import os
import json
from datetime import datetime

def ping_host(ip_address: str, timeout: int = None) -> dict:
    """
    Executes an OS-level ping command to determine if a host is reachable.
    
    Args:
        ip_address (str): The target IP address.
        timeout (int): Timeout in seconds. Defaults to env var SCANNER_PING_TIMEOUT or 2.
    
    Returns:
        dict: A JSON-compatible dictionary with ping results.
    """
    if timeout is None:
        timeout = int(os.environ.get("SCANNER_PING_TIMEOUT", 2))
    
    system = platform.system().lower()
    
    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_address]
    elif system == "darwin":
        # macOS ping uses -W for timeout in milliseconds
        command = ["ping", "-c", "1", "-W", str(timeout * 1000), ip_address]
    else:
        # Linux ping uses -W for timeout in seconds
        command = ["ping", "-c", "1", "-W", str(timeout), ip_address]
    
    start_time = datetime.now()
    try:
        # Execute the ping command
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 2  # slightly longer than the ping timeout to prevent hanging proc
        )
        is_alive = result.returncode == 0
        
        # Parse response time if possible
        response_time_ms = None
        if is_alive:
            # Very basic parsing, could be improved with regex for cross-platform robustness
            # Look for 'time=' or 'time<' 
            for word in result.stdout.split():
                if word.startswith('time=') or word.startswith('time<'):
                    try:
                        time_str = word.split('=')[1] if '=' in word else word.split('<')[1]
                        response_time_ms = int(float(time_str.replace('ms', '')))
                        break
                    except ValueError:
                        pass
        
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        is_alive = False
        response_time_ms = None
    
    end_time = datetime.now()
        
    return {
        "ip_address": ip_address,
        "timestamp": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
        "is_alive": is_alive,
        "response_time_ms": response_time_ms
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone Ping Component")
    parser.add_argument("--ip", required=True, help="IP address to ping")
    args = parser.parse_args()
    
    result = ping_host(args.ip)
    print(json.dumps(result, indent=2))
