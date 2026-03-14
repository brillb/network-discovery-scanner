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

import argparse
import os
import sys

from flask import Flask, abort, render_template
from sqlalchemy import text

from browser_common import extract_scan_time, normalize_vendor, resolve_evidence_path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from db_loader import describe_database, load_database

app = Flask(__name__)
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

TARGET_DIR = ""
DB_HANDLE = None
DATABASE_ALIAS = ""
DATABASE_DISPLAY_NAME = ""
DATABASE_DESCRIPTION = ""

MANAGED_ADDRESS_CTE = """
WITH managed_addresses AS (
    SELECT
        d.id AS device_id,
        d.ip_address AS address,
        d.ip_address AS primary_ip
    FROM devices d
    WHERE d.ip_address IS NOT NULL AND d.ip_address <> ''
    UNION
    SELECT
        di.device_id AS device_id,
        di.ip_address AS address,
        d.ip_address AS primary_ip
    FROM device_interfaces di
    JOIN devices d ON d.id = di.device_id
    WHERE di.ip_address IS NOT NULL AND di.ip_address <> ''
)
"""


def fetch_rows(conn, query, params=None):
    return [dict(row) for row in conn.execute(text(query), params or {}).mappings().all()]


def fetch_one(conn, query, params=None):
    row = conn.execute(text(query), params or {}).mappings().first()
    return dict(row) if row else None


def get_db_connection(dbname):
    if dbname != DATABASE_ALIAS or DB_HANDLE is None:
        abort(404, description="Database not found")

    return DB_HANDLE.engine.connect()


@app.route("/")
def index():
    databases = []
    if DB_HANDLE is not None:
        databases.append(
            {
                "key": DATABASE_ALIAS,
                "label": DATABASE_DISPLAY_NAME,
                "description": DATABASE_DESCRIPTION,
            }
        )

    return render_template("index.html", databases=databases, directory=TARGET_DIR)


@app.route("/db/<dbname>")
def view_db(dbname):
    conn = get_db_connection(dbname)

    try:
        query = """
        WITH latest_devices AS (
            SELECT
                d.id,
                d.ip_address,
                d.scan_time,
                d.last_error,
                ROW_NUMBER() OVER (
                    PARTITION BY d.ip_address
                    ORDER BY d.scan_time DESC, d.id DESC
                ) AS rn
            FROM devices d
            WHERE d.ip_address IS NOT NULL AND d.ip_address <> ''
        )
        SELECT
            ld.ip_address AS ip,
            ld.scan_time AS latest_scan,
            ld.last_error,
            i.hostname,
            i.hardware_product,
            i.model,
            i.serial_number
        FROM latest_devices ld
        LEFT JOIN device_inventory i ON i.device_id = ld.id
        WHERE ld.rn = 1
        ORDER BY ld.ip_address
        """
        devices = fetch_rows(conn, query)
    finally:
        conn.close()

    for device in devices:
        vendor = normalize_vendor(
            device.get("hardware_product"),
            device.get("model"),
            device.get("hostname"),
        )
        device["vendor"] = vendor
        device["vendor_class"] = vendor.lower().replace(" ", "-")

    return render_template("db_view.html", dbname=dbname, db_label=DATABASE_DISPLAY_NAME, devices=devices)


@app.route("/db/<dbname>/device/<ip>")
def view_device(dbname, ip):
    conn = get_db_connection(dbname)

    try:
        device_row = fetch_one(
            conn,
            """
            SELECT id, scan_time, is_alive, ping_responded, ssh_port_open, snmp_responded, ssh_responded, last_error
            FROM devices
            WHERE ip_address = :ip
            ORDER BY scan_time DESC, id DESC
            LIMIT 1
            """,
            {"ip": ip},
        )

        if not device_row:
            abort(404, description="Device IP not found in database")

        dev_id = device_row["id"]
        base_scan_data = {
            "is_alive": device_row["is_alive"],
            "ping_responded": device_row["ping_responded"],
            "ssh_port_open": device_row["ssh_port_open"],
            "snmp_responded": device_row["snmp_responded"],
            "ssh_responded": device_row["ssh_responded"],
            "last_error": device_row.get("last_error") or "",
        }

        inv = fetch_one(
            conn,
            "SELECT * FROM device_inventory WHERE device_id = :device_id",
            {"device_id": dev_id},
        )
        if inv:
            base_scan_data.update(inv)

        interfaces = fetch_rows(
            conn,
            """
            SELECT DISTINCT i.interface_name, i.ip_address, i.subnet_mask
            FROM device_interfaces i
            JOIN devices d ON i.device_id = d.id
            WHERE d.ip_address = :ip
            """,
            {"ip": ip},
        )

        neighbors = fetch_rows(
            conn,
            MANAGED_ADDRESS_CTE + """
            SELECT DISTINCT
                COALESCE(NULLIF(n.neighbor_hostname, 'Unknown'), target_inv.hostname, n.neighbor_hostname, 'Unknown') AS neighbor_hostname,
                COALESCE(target_d.ip_address, n.neighbor_ip) AS neighbor_ip,
                n.local_port,
                n.remote_port,
                n.protocol,
                n.neighbor_ip AS observed_neighbor_ip,
                target_d.ip_address AS resolved_device_ip
            FROM device_neighbors n
            JOIN devices d ON n.device_id = d.id
            LEFT JOIN managed_addresses target_addr ON target_addr.address = n.neighbor_ip
            LEFT JOIN devices target_d ON target_d.id = target_addr.device_id
            LEFT JOIN device_inventory target_inv ON target_inv.device_id = target_d.id
            WHERE d.ip_address = :ip
            """,
            {"ip": ip},
        )

        seen_by = fetch_rows(
            conn,
            MANAGED_ADDRESS_CTE + """
            SELECT DISTINCT
                i.hostname as source_hostname,
                d.ip_address as source_ip,
                n.local_port as remote_port_on_source,
                n.remote_port as local_port_on_this,
                n.protocol,
                target_addr.address AS matched_address
            FROM device_neighbors n
            JOIN devices d ON n.device_id = d.id
            LEFT JOIN device_inventory i ON d.id = i.device_id
            JOIN managed_addresses target_addr ON target_addr.address = n.neighbor_ip
            WHERE target_addr.primary_ip = :ip
            """,
            {"ip": ip},
        )

        config_rows = fetch_rows(
            conn,
            """
            SELECT dc.*
            FROM device_configs dc
            JOIN devices d ON d.id = dc.device_id
            WHERE d.ip_address = :ip
            ORDER BY dc.id DESC
            """,
            {"ip": ip},
        )
    finally:
        conn.close()

    scans = []

    for cfg in config_rows:
        scan_data = dict(base_scan_data)
        scan_data.update(
            {
                "id": cfg["id"],
                "scan_time": extract_scan_time(cfg.get("evidence_file_path"), fallback=device_row["scan_time"]),
                "interfaces": interfaces,
                "neighbors": neighbors,
                "seen_by": seen_by,
                "config_info": cfg,
                "config_content": "",
            }
        )

        if cfg.get("evidence_file_path"):
            full_path = resolve_evidence_path(TARGET_DIR, cfg["evidence_file_path"])

            try:
                if full_path and os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8") as handle:
                        scan_data["config_content"] = handle.read()
            except Exception as exc:
                scan_data["config_content"] = f"Error reading evidence: {exc}"

        scans.append(scan_data)

    if not scans:
        scan_data = dict(base_scan_data)
        scan_data.update(
            {
                "id": f"device-{dev_id}",
                "scan_time": device_row["scan_time"],
                "interfaces": interfaces,
                "neighbors": neighbors,
                "seen_by": seen_by,
                "config_info": None,
                "config_content": "",
            }
        )
        scans.append(scan_data)

    return render_template(
        "device_view.html",
        dbname=dbname,
        db_label=DATABASE_DISPLAY_NAME,
        ip_address=ip,
        scans=scans,
        latest=scans[0],
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner UI")
    parser.add_argument("--dbconfig", required=True, help="YAML database configuration file")
    parser.add_argument("--directory", default="", help="Directory containing evidence folders referenced by the database")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the web server on")
    parser.add_argument("--bind-all", action="store_true", help="Bind to 0.0.0.0 instead of 127.0.0.1")

    args = parser.parse_args()
    DB_HANDLE = load_database(args.dbconfig, initialize=True)
    DATABASE_ALIAS = DB_HANDLE.alias
    DATABASE_DISPLAY_NAME = DB_HANDLE.display_name
    DATABASE_DESCRIPTION = describe_database(DB_HANDLE.config)

    if args.directory:
        TARGET_DIR = os.path.abspath(args.directory)
    elif DB_HANDLE.config["type"] == "sqlite":
        TARGET_DIR = os.path.dirname(DB_HANDLE.config["dbfile"])
    else:
        TARGET_DIR = os.getcwd()

    bind_host = "0.0.0.0" if args.bind_all else "127.0.0.1"

    print("Starting Network Scanner UI...")
    print(f"Configured database: {DATABASE_DESCRIPTION}")
    print(f"Evidence directory: {TARGET_DIR}")
    print(f"Bind host: {bind_host}")
    print(f"Access at http://{bind_host}:{args.port}/")

    app.run(host=bind_host, port=args.port, debug=True)
