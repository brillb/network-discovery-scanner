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

import sqlite3
import os
import random
import datetime
import argparse

EVIDENCE_DIR_BASE = "discovered_device_evidence"

# Setup schema
SCHEMA = """
DROP TABLE IF EXISTS devices;
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT,
    scan_time DATETIME,
    is_alive BOOLEAN,
    ping_responded BOOLEAN,
    ssh_port_open BOOLEAN,
    snmp_responded BOOLEAN,
    ssh_responded BOOLEAN,
    last_error TEXT
);

DROP TABLE IF EXISTS device_inventory;
CREATE TABLE device_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    hostname TEXT,
    hardware_product TEXT,
    model TEXT,
    hardware_version TEXT,
    software_image TEXT,
    software_version TEXT,
    serial_number TEXT,
    uptime_seconds INTEGER,
    power_status TEXT,
    working_snmp_credential TEXT,
    working_ssh_credential TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

DROP TABLE IF EXISTS device_interfaces;
CREATE TABLE device_interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    interface_name TEXT,
    ip_address TEXT,
    subnet_mask TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

DROP TABLE IF EXISTS device_neighbors;
CREATE TABLE device_neighbors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    neighbor_hostname TEXT,
    neighbor_ip TEXT,
    local_port TEXT,
    remote_port TEXT,
    protocol TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

DROP TABLE IF EXISTS device_configs;
CREATE TABLE device_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    working_ssh_credential TEXT,
    evidence_file_path TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);
"""

def get_random_time(days_ago_min, days_ago_max):
    now = datetime.datetime.now()
    delta = datetime.timedelta(
        days=random.randint(days_ago_min, days_ago_max),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )
    return now - delta

def generate_config_content(hostname, ip_address, device_type):
    config = f"""!
! Mock Running Config for {hostname} ({ip_address})
! Device Type: {device_type}
! Generated: {datetime.datetime.now()}
!
version 15.2
no service pad
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname {hostname}
!
boot-start-marker
boot-end-marker
!
"""
    if device_type == "Switch":
        config += """!
vlan 10
 name Users
vlan 20
 name Servers
!
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 10
 spanning-tree portfast
!
interface GigabitEthernet0/2
 switchport mode trunk
!
"""
    else:
        config += """!
interface GigabitEthernet0/0/0
 ip address 10.100.1.1 255.255.255.0
 negotiation auto
!
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
!
"""
    config += """!
line con 0
line vty 0 4
 login local
 transport input ssh
!
end
"""
    return config

def main():
    parser = argparse.ArgumentParser(description="Generate mock discovery data.")
    parser.add_argument("--directory", default=".", help="Directory to output the SQLite database and evidence folders")
    args = parser.parse_args()
    
    target_dir = os.path.abspath(args.directory)
    os.makedirs(target_dir, exist_ok=True)
    
    db_path = os.path.join(target_dir, "sample_discovery.db")
    db_config_path = os.path.join(target_dir, "db.yaml")
    if os.path.exists(db_path):
        os.remove(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.executescript(SCHEMA)

    vendors = [
        ("Cisco", "Catalyst 3850", "Switch"),
        ("Juniper", "EX4300", "Switch"),
        ("Cisco", "ISR 4321", "Router"),
        ("Arista", "7050X", "Switch"),
        ("Palo Alto", "PA-3220", "Firewall"),
    ]

    # Pre-generate IPs and types
    devices_info = []
    for i in range(1, 21):
        ip = f"10.0.0.{i}"
        vendor, model, dev_type = random.choice(vendors)
        hostname = f"{dev_type[:2].lower()}-{vendor[:3].lower()}-{i:02d}"
        devices_info.append({
            "ip": ip,
            "vendor": vendor,
            "model": model,
            "type": dev_type,
            "hostname": hostname
        })

    # We will generate scans for two explicit batch times
    scan_times = [
        datetime.datetime(2026, 3, 5, 12, 0, 0),
        datetime.datetime(2026, 3, 6, 14, 0, 0)
    ]
    
    for info in devices_info:
        for scan_time in scan_times:
            time_str_dir = scan_time.strftime("%Y%m%d_%H%M%S")
            time_str_db = scan_time.strftime("%Y-%m-%d %H:%M:%S")
            is_latest_scan = scan_time == scan_times[-1]
            degraded_unknown = is_latest_scan and info["ip"] == "10.0.0.6"
            degraded_partial = is_latest_scan and info["ip"] == "10.0.0.18"

            # Create evidence dir
            # The path referenced inside the DB
            evidence_dir_db_relative = f"{EVIDENCE_DIR_BASE}_{time_str_dir}"
            
            # The path generated on disk
            evidence_dir_absolute = os.path.join(target_dir, evidence_dir_db_relative)
            os.makedirs(evidence_dir_absolute, exist_ok=True)

            # Insert device
            snmp_responded = not degraded_unknown
            ssh_responded = not (degraded_unknown or degraded_partial)
            last_error = ""
            if degraded_unknown:
                last_error = "snmp:no_valid_keys [demo:usm_auth_failure]; ssh:no_valid_keys [demo:auth_failure]"
            elif degraded_partial:
                last_error = "snmp:partial_inventory [demo:entity_mib_unavailable]; ssh:no_valid_keys [demo:auth_failure]"
            cursor.execute("""
                INSERT INTO devices (ip_address, scan_time, is_alive, ping_responded, ssh_port_open, snmp_responded, ssh_responded, last_error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (info["ip"], time_str_db, True, True, True, snmp_responded, ssh_responded, last_error))
            
            device_id = cursor.lastrowid

            # Insert inventory
            sw_ver = f"15.{random.randint(1, 5)}.{random.randint(1, 9)}M" if info["vendor"] == "Cisco" else f"OS-{random.randint(10, 20)}.{random.randint(1, 9)}"
            serial_number = f"{info['vendor'][:3].upper()}-{devices_info.index(info) + 1:04d}-{scan_time.strftime('%d%H%M')}"
            if not degraded_unknown:
                working_snmp_credential = "joe_smith_keys:1" if info["vendor"] == "Cisco" else "joe_smith_keys:0"
                working_ssh_credential = "global_read_only:k1" if info["type"] in {"Router", "Firewall"} else "site_a_admin:p0"
                inventory_values = (
                    info["hostname"],
                    info["vendor"],
                    info["model"],
                    "V01",
                    "universal_k9",
                    sw_ver,
                    serial_number,
                    random.randint(3600, 864000),
                    "Normal",
                    working_snmp_credential,
                    working_ssh_credential if not degraded_partial else "",
                )
                if degraded_partial:
                    inventory_values = (
                        info["hostname"],
                        info["vendor"],
                        "",
                        "",
                        "",
                        "",
                        "",
                        random.randint(3600, 864000),
                        "Unknown",
                        working_snmp_credential,
                        "",
                    )

                cursor.execute("""
                    INSERT INTO device_inventory (device_id, hostname, hardware_product, model, hardware_version, software_image, software_version, serial_number, uptime_seconds, power_status, working_snmp_credential, working_ssh_credential)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (device_id, *inventory_values))

            # Insert interfaces
            cursor.execute("""
                INSERT INTO device_interfaces (device_id, interface_name, ip_address, subnet_mask)
                VALUES (?, ?, ?, ?)
            """, (device_id, "Vlan1" if info["type"] == "Switch" else "GigabitEthernet0/0/0", info["ip"], "255.255.255.0"))
            
            cursor.execute("""
                INSERT INTO device_interfaces (device_id, interface_name, ip_address, subnet_mask)
                VALUES (?, ?, ?, ?)
            """, (device_id, "Loopback0", f"10.255.255.{devices_info.index(info) + 1}", "255.255.255.255"))

            # Insert neighbors (randomly pick a neighbor)
            if random.random() > 0.3:
                neighbor = random.choice(devices_info)
                if neighbor != info:
                    cursor.execute("""
                        INSERT INTO device_neighbors (device_id, neighbor_hostname, neighbor_ip, local_port, remote_port, protocol)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (device_id, neighbor["hostname"], neighbor["ip"], "GigabitEthernet0/1", "GigabitEthernet0/1", "CDP"))

            # Write Config and Insert to Configs Table
            if not (degraded_unknown or degraded_partial):
                config_content = generate_config_content(info["hostname"], info["ip"], info["type"])
                # Let's add a comment string to make configs slightly unique by scan
                config_content = f"! Scan Time: {time_str_db}\n" + config_content

                filename = f"{info['ip']}-ssh-{time_str_dir}.txt"
                
                # Use strict relative forward slashes for cross-platform local web server compatibility
                filepath_db_relative = f"{evidence_dir_db_relative}/{filename}"
                
                # This is where we write the file locally from the script context
                filepath_absolute = os.path.join(evidence_dir_absolute, filename)
                
                with open(filepath_absolute, "w") as f:
                    f.write(config_content)
                    
                cursor.execute("""
                    INSERT INTO device_configs (device_id, working_ssh_credential, evidence_file_path)
                    VALUES (?, ?, ?)
                """, (device_id, working_ssh_credential, filepath_db_relative))

    conn.commit()
    conn.close()

    with open(db_config_path, "w", encoding="utf-8") as handle:
        handle.write("db:\n")
        handle.write("  type: sqlite\n")
        handle.write("  dbfile: sample_discovery.db\n")

    print("Database and mock evidence files generated successfully.")

if __name__ == "__main__":
    main()
