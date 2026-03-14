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

from flask import Flask, abort, jsonify, render_template, url_for
from sqlalchemy import text

from browser_common import (
    VENDOR_COLORS,
    extract_scan_time,
    get_display_logo_filename,
    infer_device_type,
    normalize_logo_assets,
    normalize_vendor,
    resolve_evidence_path,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from db_loader import describe_database, load_database

app = Flask(__name__)
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
normalize_logo_assets(app.static_folder)

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

    return render_template("graphical_index.html", databases=databases, directory=TARGET_DIR)


@app.route("/db/<dbname>")
def view_db(dbname):
    conn = get_db_connection(dbname)
    conn.close()
    return render_template("graphical_view.html", dbname=dbname, db_label=DATABASE_DISPLAY_NAME)


@app.route("/api/db/<dbname>/topology")
def api_topology(dbname):
    conn = get_db_connection(dbname)

    try:
        device_rows = fetch_rows(
            conn,
            """
            WITH latest_devices AS (
                SELECT
                    d.id,
                    d.ip_address,
                    d.scan_time,
                    d.last_error,
                    d.ssh_port_open,
                    ROW_NUMBER() OVER (
                        PARTITION BY d.ip_address
                        ORDER BY d.scan_time DESC, d.id DESC
                    ) AS rn
                FROM devices d
                WHERE d.ip_address IS NOT NULL AND d.ip_address <> ''
            )
            SELECT
                ld.ip_address AS ip,
                ld.last_error,
                ld.ssh_port_open,
                i.hostname,
                i.hardware_product,
                i.model,
                i.software_image,
                i.working_snmp_credential,
                i.working_ssh_credential
            FROM latest_devices ld
            LEFT JOIN device_inventory i ON i.device_id = ld.id
            WHERE ld.rn = 1
            """
        )

        neighbor_rows = fetch_rows(
            conn,
            MANAGED_ADDRESS_CTE + """
            SELECT DISTINCT
                d.ip_address as source_ip,
                target_addr.primary_ip as target_ip,
                n.neighbor_ip as observed_neighbor_ip,
                n.local_port,
                n.remote_port,
                n.protocol
            FROM device_neighbors n
            JOIN devices d ON n.device_id = d.id
            LEFT JOIN managed_addresses target_addr ON target_addr.address = n.neighbor_ip
            WHERE target_addr.primary_ip IS NOT NULL
            """
        )
    finally:
        conn.close()

    nodes = []
    node_ids = set()

    for row in device_rows:
        ip = row["ip"]
        hostname = row.get("hostname") or ip
        last_error = row.get("last_error") or ""
        hardware_product = row.get("hardware_product") or "Unknown"
        model = row.get("model") or "Unknown"
        software_image = row.get("software_image") or ""
        ssh_port_open = row.get("ssh_port_open")
        working_snmp_credential = row.get("working_snmp_credential") or ""
        working_ssh_credential = row.get("working_ssh_credential") or ""

        vendor = normalize_vendor(hardware_product, model, software_image, hostname)
        dev_type = infer_device_type(
            hostname=hostname,
            vendor=vendor,
            model=model,
            hardware_product=hardware_product,
            software_image=software_image,
        )

        color = VENDOR_COLORS.get(vendor, VENDOR_COLORS["Unknown"])
        display_logo_filename = get_display_logo_filename(vendor, dev_type)
        logo_url = url_for("static", filename=f"logos_display/{display_logo_filename}")
        node_shape = "circularImage" if dev_type == "Router" else "image"

        node_ids.add(ip)
        nodes.append(
            {
                "id": ip,
                "label": f"{hostname}*" if last_error else hostname,
                "title": (
                    f"IP: {ip}<br>Vendor: {vendor}<br>Model: {model}"
                    f"<br>TCP/22: {'Open' if ssh_port_open else 'Closed'}"
                    + (f"<br>SNMP Credential: {working_snmp_credential}" if working_snmp_credential else "")
                    + (f"<br>SSH Credential: {working_ssh_credential}" if working_ssh_credential else "")
                    + (f"<br>Error: {last_error}" if last_error else "")
                ),
                "shape": node_shape,
                "image": logo_url,
                "brokenImage": url_for(
                    "static",
                    filename=f"logos_display/{get_display_logo_filename('Unknown', 'Unknown')}",
                ),
                "size": 28,
                "color": {
                    "border": color,
                    "background": "#ffffff",
                    "highlight": {
                        "border": color,
                        "background": "#ffffff",
                    },
                },
                "borderWidth": 2,
                "borderWidthSelected": 3,
                "metaData": {
                    "ip": ip,
                    "hostname": hostname,
                    "vendor": vendor,
                    "model": model,
                    "type": dev_type,
                    "color": color,
                    "logo": logo_url,
                    "nodeShape": node_shape,
                    "ssh_port_open": ssh_port_open,
                    "working_snmp_credential": working_snmp_credential,
                    "working_ssh_credential": working_ssh_credential,
                    "last_error": last_error,
                },
            }
        )

    edges = []
    seen_links = set()

    for row in neighbor_rows:
        src = row["source_ip"]
        dst = row["target_ip"]
        if dst in node_ids and src in node_ids:
            protocol = row.get("protocol") or "Unknown"
            link_id = (src, dst, protocol, row.get("local_port"), row.get("remote_port"))
            if link_id not in seen_links:
                seen_links.add(link_id)
                edges.append(
                    {
                        "from": src,
                        "to": dst,
                        "title": f"{protocol}: {row.get('local_port')} <-> {row.get('remote_port')}",
                        "dashes": protocol.upper() == "BGP",
                        "arrows": "to" if protocol.upper() == "BGP" else "",
                        "smooth": {
                            "enabled": True,
                            "type": "curvedCW" if protocol.upper() == "BGP" else "continuous",
                            "roundness": 0.18 if protocol.upper() == "BGP" else 0.0,
                        },
                    }
                )

    return jsonify({"nodes": nodes, "edges": edges})


@app.route("/api/db/<dbname>/device/<ip>")
def api_device_details(dbname, ip):
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
            return jsonify({"error": "Device not found"}), 404

        device_id = device_row["id"]
        master_data = {
            "ip": ip,
            "latest_scan_time": device_row["scan_time"],
            "is_alive": device_row["is_alive"],
            "ping_responded": device_row["ping_responded"],
            "ssh_port_open": device_row["ssh_port_open"],
            "snmp_responded": device_row["snmp_responded"],
            "ssh_responded": device_row["ssh_responded"],
            "last_error": device_row.get("last_error") or "",
            "scans": [],
        }

        inv = fetch_one(
            conn,
            "SELECT * FROM device_inventory WHERE device_id = :device_id",
            {"device_id": device_id},
        )
        if inv:
            master_data.update(inv)

        master_data["vendor"] = normalize_vendor(
            master_data.get("hardware_product"),
            master_data.get("model"),
            master_data.get("software_image"),
            master_data.get("hostname"),
        )
        master_data["type"] = infer_device_type(
            hostname=master_data.get("hostname", ""),
            vendor=master_data["vendor"],
            model=master_data.get("model", ""),
            hardware_product=master_data.get("hardware_product", ""),
            software_image=master_data.get("software_image", ""),
        )
        master_data["vendor_color"] = VENDOR_COLORS.get(master_data["vendor"], VENDOR_COLORS["Unknown"])
        master_data["logo"] = url_for(
            "static",
            filename=f"logos_display/{get_display_logo_filename(master_data['vendor'], master_data['type'])}",
        )

        master_data["interfaces"] = fetch_rows(
            conn,
            """
            SELECT DISTINCT i.interface_name, i.ip_address, i.subnet_mask
            FROM device_interfaces i
            JOIN devices d ON i.device_id = d.id
            WHERE d.ip_address = :ip
            """,
            {"ip": ip},
        )

        master_data["neighbors"] = fetch_rows(
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

        master_data["seen_by"] = fetch_rows(
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

    for cfg in config_rows:
        scan_entry = {
            "id": cfg["id"],
            "scan_time": extract_scan_time(cfg.get("evidence_file_path"), fallback=device_row["scan_time"]),
            "working_ssh_credential": cfg.get("working_ssh_credential"),
            "evidence_file_path": cfg.get("evidence_file_path"),
            "config_content": "",
        }

        if cfg.get("evidence_file_path"):
            full_path = resolve_evidence_path(TARGET_DIR, cfg["evidence_file_path"])

            try:
                if full_path and os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8") as handle:
                        scan_entry["config_content"] = handle.read()
            except Exception:
                scan_entry["config_content"] = "Error reading evidence."

        master_data["scans"].append(scan_entry)

    if not master_data["scans"]:
        master_data["scans"].append(
            {
                "id": f"device-{device_id}",
                "scan_time": device_row["scan_time"],
                "working_ssh_credential": master_data.get("working_ssh_credential", ""),
                "evidence_file_path": "",
                "config_content": "",
            }
        )

    return jsonify(master_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Scanner Graphical UI")
    parser.add_argument("--dbconfig", required=True, help="YAML database configuration file")
    parser.add_argument("--directory", default="", help="Directory containing evidence folders referenced by the database")
    parser.add_argument("--port", type=int, default=5001, help="Port to run the graphical web server on")
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

    print("Starting Network Scanner Graphical UI...")
    print(f"Configured database: {DATABASE_DESCRIPTION}")
    print(f"Evidence directory: {TARGET_DIR}")
    print(f"Bind host: {bind_host}")
    print(f"Access at http://{bind_host}:{args.port}/")

    app.run(host=bind_host, port=args.port, debug=True)
