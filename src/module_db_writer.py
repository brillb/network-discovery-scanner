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
Database writer utilities for the single-IP discovery pipeline.
"""
from datetime import datetime

from sqlalchemy import insert, select, text, update

from db_loader import device_configs, device_inventory, devices


class DatabaseWriter:
    def __init__(self, db_conn):
        self.db_conn = db_conn

    def __del__(self):
        try:
            db_conn = getattr(self, "db_conn", None)
            if db_conn is None:
                return
            if getattr(db_conn, "closed", False):
                return
            self.commit()
        except Exception:
            pass

    def commit(self):
        self.db_conn.commit()

    def rollback(self):
        self.db_conn.rollback()

    def ensure_device(self, ip_address):
        row = self.db_conn.execute(
            select(devices.c.id).where(devices.c.ip_address == ip_address)
        ).first()
        if row:
            return row[0]

        insert_result = self.db_conn.execute(
            insert(devices).values(
                ip_address=ip_address,
                scan_time=self._current_timestamp(),
                last_error="",
            )
        )
        return insert_result.inserted_primary_key[0]

    def record_reachability(self, device_id, *, ping_responded, ssh_port_open, scanned_at=None):
        is_alive = bool(ping_responded) or bool(ssh_port_open)
        self.db_conn.execute(
            update(devices)
            .where(devices.c.id == device_id)
            .values(
                is_alive=is_alive,
                ping_responded=bool(ping_responded),
                ssh_port_open=bool(ssh_port_open),
                scan_time=scanned_at or self._current_timestamp(),
                last_error="",
            )
        )
        return is_alive

    def record_snmp_success(self, device_id, *, inventory, interfaces=None, neighbors=None, working_credential_ref=None):
        self.upsert_inventory(
            device_id,
            {
                "hostname": inventory.get("hostname"),
                "hardware_product": inventory.get("hardware_product"),
                "model": inventory.get("model"),
                "hardware_version": inventory.get("hardware_version"),
                "software_image": inventory.get("software_image"),
                "software_version": inventory.get("software_version"),
                "serial_number": inventory.get("serial_number"),
                "uptime_seconds": inventory.get("uptime_seconds"),
                "power_status": inventory.get("power_status"),
                "working_snmp_credential": working_credential_ref,
            },
        )

        for iface in self._dedupe_interfaces(interfaces or []):
            self.insert_interface(
                device_id,
                iface.get("name"),
                iface.get("ip"),
                iface.get("mask"),
            )

        for neighbor in self._dedupe_neighbors(neighbors or []):
            self.insert_neighbor(
                device_id,
                neighbor.get("neighbor_hostname"),
                neighbor.get("neighbor_ip"),
                neighbor.get("local_port"),
                neighbor.get("remote_port"),
                neighbor.get("protocol"),
            )

        self.db_conn.execute(
            update(devices).where(devices.c.id == device_id).values(snmp_responded=True)
        )

    def record_snmp_failure(self, device_id):
        self.db_conn.execute(
            update(devices).where(devices.c.id == device_id).values(snmp_responded=False)
        )

    def record_ssh_success(self, device_id, *, working_credential_ref, evidence_file_path):
        self.upsert_inventory(
            device_id,
            {"working_ssh_credential": working_credential_ref},
        )
        self.db_conn.execute(
            insert(device_configs).values(
                device_id=device_id,
                working_ssh_credential=working_credential_ref,
                evidence_file_path=evidence_file_path,
            )
        )
        self.db_conn.execute(
            update(devices).where(devices.c.id == device_id).values(ssh_responded=True)
        )

    def record_ssh_failure(self, device_id):
        self.db_conn.execute(
            update(devices).where(devices.c.id == device_id).values(ssh_responded=False)
        )

    def write_last_error(self, device_id, errors):
        self.db_conn.execute(
            update(devices)
            .where(devices.c.id == device_id)
            .values(last_error=self._format_last_error(errors))
        )

    def upsert_inventory(self, device_id, values):
        inventory_row = self._get_inventory_row(device_id)
        normalized_values = {"device_id": device_id}

        for key, value in values.items():
            normalized_values[key] = value

        if inventory_row:
            update_values = dict(normalized_values)
            update_values.pop("device_id", None)
            self.db_conn.execute(
                update(device_inventory)
                .where(device_inventory.c.device_id == device_id)
                .values(**update_values)
            )
            return

        self.db_conn.execute(insert(device_inventory).values(**normalized_values))

    def insert_interface(self, device_id, interface_name, ip_address, subnet_mask):
        existing_rows = self.db_conn.execute(
            text("""
                SELECT id, ip_address, subnet_mask
                FROM device_interfaces
                WHERE device_id = :device_id AND interface_name = :interface_name
                ORDER BY id ASC
            """),
            {"device_id": device_id, "interface_name": interface_name},
        ).mappings().all()

        normalized_ip = self._normalize_text(ip_address)
        normalized_mask = self._normalize_text(subnet_mask)

        for row in existing_rows:
            existing_ip = row["ip_address"] or ""
            existing_mask = row["subnet_mask"] or ""
            if existing_ip == normalized_ip and existing_mask == normalized_mask:
                return

        if existing_rows:
            if not normalized_ip and not normalized_mask:
                return

            for row in existing_rows:
                existing_ip = row["ip_address"] or ""
                existing_mask = row["subnet_mask"] or ""

                updated_ip = existing_ip
                updated_mask = existing_mask
                changed = False

                if normalized_ip and not existing_ip:
                    updated_ip = normalized_ip
                    changed = True
                if normalized_mask and not existing_mask:
                    updated_mask = normalized_mask
                    changed = True

                if changed:
                    self.db_conn.execute(
                        text("""
                            UPDATE device_interfaces
                            SET ip_address = :ip_address, subnet_mask = :subnet_mask
                            WHERE id = :row_id
                        """),
                        {
                            "ip_address": updated_ip,
                            "subnet_mask": updated_mask,
                            "row_id": row["id"],
                        },
                    )
                    return

            return

        self.db_conn.execute(
            text("""
                INSERT INTO device_interfaces (device_id, interface_name, ip_address, subnet_mask)
                VALUES (:device_id, :interface_name, :ip_address, :subnet_mask)
            """),
            {
                "device_id": device_id,
                "interface_name": interface_name,
                "ip_address": normalized_ip,
                "subnet_mask": normalized_mask,
            },
        )

    def insert_neighbor(self, device_id, neighbor_hostname, neighbor_ip, local_port, remote_port, protocol):
        existing_neighbor = self.db_conn.execute(
            text("""
                SELECT 1
                FROM device_neighbors
                WHERE device_id = :device_id
                  AND neighbor_hostname = :neighbor_hostname
                  AND neighbor_ip = :neighbor_ip
                  AND local_port = :local_port
                  AND remote_port = :remote_port
                  AND protocol = :protocol
                LIMIT 1
            """),
            {
                "device_id": device_id,
                "neighbor_hostname": neighbor_hostname,
                "neighbor_ip": neighbor_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
            },
        ).first()
        if existing_neighbor:
            return

        self.db_conn.execute(
            text("""
                INSERT INTO device_neighbors (device_id, neighbor_hostname, neighbor_ip, local_port, remote_port, protocol)
                VALUES (:device_id, :neighbor_hostname, :neighbor_ip, :local_port, :remote_port, :protocol)
            """),
            {
                "device_id": device_id,
                "neighbor_hostname": neighbor_hostname,
                "neighbor_ip": neighbor_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
            },
        )

    def _current_timestamp(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _format_last_error(self, errors):
        cleaned = [str(error).strip() for error in errors if str(error).strip()]
        return " | ".join(cleaned)

    def _get_inventory_row(self, device_id):
        return self.db_conn.execute(
            select(device_inventory.c.id).where(device_inventory.c.device_id == device_id)
        ).first()

    def _dedupe_interfaces(self, interfaces):
        seen = set()
        deduped = []
        for iface in interfaces:
            key = (iface.get("name"), iface.get("ip"), iface.get("mask"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(iface)
        return deduped

    def _dedupe_neighbors(self, neighbors):
        seen = set()
        deduped = []
        for neighbor in neighbors:
            key = (
                neighbor.get("neighbor_hostname"),
                neighbor.get("neighbor_ip"),
                neighbor.get("local_port"),
                neighbor.get("remote_port"),
                neighbor.get("protocol"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(neighbor)
        return deduped

    def _normalize_text(self, value):
        return value or ""


class ScanResultWriter:
    def __init__(self, db_conn):
        self.writer = DatabaseWriter(db_conn)

    def persist_scan_result(self, result):
        device_id = self.writer.ensure_device(result.ip)

        try:
            if result.reachability is not None:
                is_alive = self.writer.record_reachability(
                    device_id,
                    ping_responded=result.reachability.ping_responded,
                    ssh_port_open=result.reachability.ssh_port_open,
                    scanned_at=result.finished_at,
                )
                if not is_alive:
                    self.writer.record_snmp_failure(device_id)
                    self.writer.record_ssh_failure(device_id)

            if result.snmp is not None and result.snmp.attempted:
                if result.snmp.succeeded:
                    self.writer.record_snmp_success(
                        device_id,
                        inventory=result.snmp.inventory,
                        interfaces=result.snmp.interfaces,
                        neighbors=result.snmp.neighbors,
                        working_credential_ref=result.snmp.working_credential_ref,
                    )
                else:
                    self.writer.record_snmp_failure(device_id)

            if result.ssh is not None and result.ssh.attempted:
                if result.ssh.succeeded:
                    self.writer.record_ssh_success(
                        device_id,
                        working_credential_ref=result.ssh.working_credential_ref,
                        evidence_file_path=result.ssh.evidence_file_path,
                    )
                else:
                    self.writer.record_ssh_failure(device_id)

            self.writer.write_last_error(device_id, result.errors)
            self.writer.commit()
        except Exception:
            self.writer.rollback()
            raise
