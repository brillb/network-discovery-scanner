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
Component: SNMP
Handles SNMP polling (v2c and v3) for inventory, topology, and health metrics.
"""
from pysnmp.hlapi.v3arch.asyncio import *
import argparse
import asyncio
import ipaddress
import json
import os
import re


SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID_OID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"

IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
IF_NAME_OID = "1.3.6.1.2.1.31.1.1.1.1"
IP_ADDR_OID = "1.3.6.1.2.1.4.20.1.1"
IP_IFINDEX_OID = "1.3.6.1.2.1.4.20.1.2"
IP_NETMASK_OID = "1.3.6.1.2.1.4.20.1.3"
IP_ADDRESS_IFINDEX_OID = "1.3.6.1.2.1.4.34.1.3"
IP_ADDRESS_PREFIX_OID = "1.3.6.1.2.1.4.34.1.5"

LLDP_LOC_PORT_DESC_OID = "1.0.8802.1.1.2.1.3.7.1.4"
LLDP_REM_PORT_DESC_OID = "1.0.8802.1.1.2.1.4.1.1.8"
LLDP_REM_SYS_NAME_OID = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_CHASSIS_ID_SUBTYPE_OID = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID_OID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_MAN_ADDR_OID = "1.0.8802.1.1.2.1.4.2.1.2"

CDP_CACHE_ADDRESS_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
CDP_CACHE_DEVICE_ID_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"

BGP_PEER_REMOTE_ADDR_OID = "1.3.6.1.2.1.15.3.1.7"
BGP_PEER_STATE_OID = "1.3.6.1.2.1.15.3.1.2"
OSPF_NBR_IP_ADDR_OID = "1.3.6.1.2.1.14.10.1.1"

CBGP_PEER2_REMOTE_ADDR_OID = "1.3.6.1.4.1.9.9.187.1.2.5.1.2"
CBGP_PEER2_STATE_OID = "1.3.6.1.4.1.9.9.187.1.2.5.1.3"

ENT_PHYSICAL_CLASS_OID = "1.3.6.1.2.1.47.1.1.1.1.5"
ENT_PHYSICAL_NAME_OID = "1.3.6.1.2.1.47.1.1.1.1.7"
ENT_PHYSICAL_HARDWARE_REV_OID = "1.3.6.1.2.1.47.1.1.1.1.8"
ENT_PHYSICAL_SOFTWARE_REV_OID = "1.3.6.1.2.1.47.1.1.1.1.10"
ENT_PHYSICAL_SERIAL_NUM_OID = "1.3.6.1.2.1.47.1.1.1.1.11"
ENT_PHYSICAL_MODEL_NAME_OID = "1.3.6.1.2.1.47.1.1.1.1.13"
ENT_PHYSICAL_DESCR_OID = "1.3.6.1.2.1.47.1.1.1.1.2"

CISCO_SYSOBJECTID_MAP = {
    "1.3.6.1.4.1.9.1.3004": "C8000V",
}


def _sanitize_text(value):
    if value is None:
        return ""

    text = str(value).strip()
    if not text:
        return ""

    text = text.replace("\x00", "").strip()
    text = re.sub(r"\s+", " ", text)

    if text.lower() in {"unknown", "none", "null", "n/a"}:
        return ""

    if text.startswith("0x"):
        try:
            raw = bytes.fromhex(text[2:])
            decoded = raw.decode("utf-8", errors="ignore").replace("\x00", "").strip()
            if decoded and decoded.isprintable():
                text = decoded
        except ValueError:
            pass

    return text


def _snmp_value_to_text(value):
    if hasattr(value, "asOctets"):
        try:
            raw = value.asOctets()
            if raw:
                decoded = raw.decode("utf-8", errors="ignore").replace("\x00", "").strip()
                if decoded and decoded.isprintable():
                    return _sanitize_text(decoded)
        except Exception:
            pass

    return _sanitize_text(value)


def _snmp_value_to_hex_or_text(value):
    if hasattr(value, "asOctets"):
        try:
            raw = value.asOctets()
            if raw:
                decoded = raw.decode("utf-8", errors="ignore").replace("\x00", "").strip()
                if decoded and decoded.isprintable():
                    return _sanitize_text(decoded)
                return f"0x{raw.hex()}"
        except Exception:
            pass

    return _sanitize_text(value)


def _safe_ip(value):
    text = _sanitize_text(value)
    if not text:
        return ""

    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _decode_ipv4_like_value(value):
    text = _safe_ip(_snmp_value_to_text(value))
    if text:
        return text

    if hasattr(value, "asOctets"):
        try:
            raw = value.asOctets()
            if len(raw) == 4:
                return str(ipaddress.IPv4Address(raw))
        except Exception:
            pass

    if hasattr(value, "asNumbers"):
        try:
            numbers = bytes(value.asNumbers())
            if len(numbers) == 4:
                return str(ipaddress.IPv4Address(numbers))
        except Exception:
            pass

    return ""


def _prefixlen_to_mask(prefix_length):
    try:
        prefix = int(prefix_length)
    except (TypeError, ValueError):
        return ""

    if prefix < 0 or prefix > 32:
        return ""

    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return ".".join(str((bits >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def _oid_suffix(oid, base_oid):
    oid_str = str(oid)
    prefix = f"{base_oid}."
    if oid_str.startswith(prefix):
        return oid_str[len(prefix):]
    return ""


def _format_mac(raw_bytes):
    if not raw_bytes:
        return ""
    return ":".join(f"{byte:02x}" for byte in raw_bytes)


def _lldp_neighbor_index(suffix):
    parts = [part for part in suffix.split(".") if part != ""]
    if len(parts) < 3:
        return ""
    return ".".join(parts[:3])


def _parse_ios_sysdescr(sys_descr):
    parsed = {}

    image_match = re.search(r"\(([^()]+)\)", sys_descr)
    version_match = re.search(r"\bVersion\s+([^,\s]+)", sys_descr, re.IGNORECASE)

    product_match = None
    model_match = None

    for pattern in [
        r"Cisco IOS Software,\s*([^,]+)",
        r"Cisco IOS XE Software,\s*([^,]+)",
        r"Cisco IOS-XE Software,\s*([^,]+)",
    ]:
        product_match = re.search(pattern, sys_descr, re.IGNORECASE)
        if product_match:
            break

    model_match = re.search(r"\bcisco\s+([A-Z0-9][A-Za-z0-9\- ]+?)\s+\([^)]+\)\s+processor", sys_descr, re.IGNORECASE)
    if not model_match:
        model_match = re.search(r"\bWS-[A-Z0-9\-]+(?:-[A-Z0-9]+)*\b", sys_descr, re.IGNORECASE)

    if image_match:
        parsed["software_image"] = image_match.group(1).strip()
    if version_match:
        parsed["software_version"] = version_match.group(1).strip()
    if model_match:
        parsed["model"] = model_match.group(1).strip()
    if product_match:
        parsed["hardware_product"] = re.sub(r"\s+Software.*$", "", product_match.group(1).strip(), flags=re.IGNORECASE)

    if parsed.get("hardware_product") and not parsed.get("model"):
        parsed["model"] = parsed["hardware_product"]

    return parsed


def _parse_junos_sysdescr(sys_descr):
    parsed = {}
    if "junos" not in sys_descr.lower():
        return parsed

    version_match = re.search(r"JUNOS\s+([A-Za-z0-9.\-R]+)", sys_descr, re.IGNORECASE)
    model_match = re.search(r"kernel\s+([A-Za-z0-9\-]+)-", sys_descr, re.IGNORECASE)

    parsed["software_image"] = "JUNOS"
    if version_match:
        parsed["software_version"] = version_match.group(1).strip()
    if model_match:
        parsed["model"] = model_match.group(1).strip()
        parsed["hardware_product"] = model_match.group(1).strip()

    return parsed


def _parse_panos_sysdescr(sys_descr):
    parsed = {}
    if "palo alto" not in sys_descr.lower() and "pan-os" not in sys_descr.lower():
        return parsed

    version_match = re.search(r"PAN-OS\s+([A-Za-z0-9.\-]+)", sys_descr, re.IGNORECASE)
    model_match = re.search(r"\b(PA-\d+[A-Z0-9\-]*)\b", sys_descr, re.IGNORECASE)

    parsed["software_image"] = "PAN-OS"
    if version_match:
        parsed["software_version"] = version_match.group(1).strip()
    if model_match:
        parsed["model"] = model_match.group(1).strip()
        parsed["hardware_product"] = model_match.group(1).strip()

    return parsed


def _parse_sysdescr(sys_descr, sys_object_id):
    sys_descr = _sanitize_text(sys_descr)
    sys_object_id = _sanitize_text(sys_object_id)

    parsed = {
        "hardware_product": "",
        "model": "",
        "hardware_version": "",
        "software_image": "",
        "software_version": "",
        "serial_number": "",
        "power_status": "Unknown",
        "sys_descr": sys_descr,
        "sys_object_id": sys_object_id,
    }

    for parser in (_parse_ios_sysdescr, _parse_junos_sysdescr, _parse_panos_sysdescr):
        updates = parser(sys_descr)
        if updates:
            parsed.update({k: v for k, v in updates.items() if v})
            break

    if not parsed["software_image"] and sys_descr:
        parsed["software_image"] = sys_descr

    if not parsed["hardware_product"]:
        parsed["hardware_product"] = parsed["model"] or CISCO_SYSOBJECTID_MAP.get(sys_object_id, "") or sys_object_id or "Unknown"

    if not parsed["model"]:
        parsed["model"] = CISCO_SYSOBJECTID_MAP.get(sys_object_id, "") or parsed["hardware_product"]

    return parsed


def _merge_entity_inventory(inventory, ent_classes, ent_names, ent_model_names, ent_descrs, ent_hw_revs, ent_sw_revs, ent_serials):
    candidates = []

    for index in set(ent_classes) | set(ent_names) | set(ent_model_names) | set(ent_descrs) | set(ent_serials):
        candidates.append({
            "index": index,
            "entity_class": _sanitize_text(ent_classes.get(index)),
            "name": _sanitize_text(ent_names.get(index)),
            "model": _sanitize_text(ent_model_names.get(index)),
            "descr": _sanitize_text(ent_descrs.get(index)),
            "hardware_rev": _sanitize_text(ent_hw_revs.get(index)),
            "software_rev": _sanitize_text(ent_sw_revs.get(index)),
            "serial_number": _sanitize_text(ent_serials.get(index)),
        })

    def candidate_rank(candidate):
        entity_class = candidate["entity_class"].lower()
        has_serial = 1 if candidate["serial_number"] else 0
        has_model = 1 if candidate["model"] else 0
        has_name = 1 if candidate["name"] else 0
        has_descr = 1 if candidate["descr"] else 0
        class_rank = 0
        if entity_class in {"3", "chassis"}:
            class_rank = 3
        elif entity_class in {"9", "module"}:
            class_rank = 2
        elif entity_class:
            class_rank = 1
        return (class_rank, has_serial, has_model, has_name, has_descr)

    best_candidate = None
    for candidate in sorted(candidates, key=candidate_rank, reverse=True):
        if candidate["model"] or candidate["name"] or candidate["descr"]:
            best_candidate = candidate
            break

    best_serial_candidate = None
    for candidate in sorted(candidates, key=candidate_rank, reverse=True):
        if candidate["serial_number"]:
            best_serial_candidate = candidate
            break

    if not best_candidate and not best_serial_candidate:
        return inventory

    if best_candidate and best_candidate["model"]:
        inventory["hardware_product"] = best_candidate["model"]
        inventory["model"] = best_candidate["model"]
    elif best_candidate and best_candidate["name"]:
        inventory["hardware_product"] = best_candidate["name"]
        inventory["model"] = best_candidate["name"]
    elif best_candidate and best_candidate["descr"]:
        inventory["hardware_product"] = best_candidate["descr"]
        inventory["model"] = best_candidate["descr"]

    if best_candidate and best_candidate["hardware_rev"]:
        inventory["hardware_version"] = best_candidate["hardware_rev"]

    if best_candidate and best_candidate["software_rev"] and not inventory.get("software_version"):
        inventory["software_version"] = best_candidate["software_rev"]

    if best_candidate and best_candidate["serial_number"]:
        inventory["serial_number"] = best_candidate["serial_number"]
    elif best_serial_candidate and best_serial_candidate["serial_number"]:
        inventory["serial_number"] = best_serial_candidate["serial_number"]

    return inventory


async def _walk_single_map(engine, auth_data, transport, oid_string, transform=None):
    results = {}
    iterator = walk_cmd(
        engine,
        auth_data,
        transport,
        ContextData(),
        ObjectType(ObjectIdentity(oid_string)),
        lexicographicMode=False,
    )

    async for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication or error_status or not var_binds:
            continue

        oid, value = var_binds[0]
        suffix = _oid_suffix(oid, oid_string)
        if not suffix:
            continue

        if transform:
            results[suffix] = transform(value)
        else:
            results[suffix] = _snmp_value_to_text(value)

    return results


def _build_interfaces(if_descr_map, ip_addr_map, ip_mask_map, ip_ifindex_map):
    interfaces = []
    seen = set()

    for suffix, ip_addr in ip_addr_map.items():
        ip_text = _safe_ip(ip_addr)
        if not ip_text:
            continue

        if_index = _sanitize_text(ip_ifindex_map.get(suffix))
        if not if_index:
            continue

        interface_name = _sanitize_text(if_descr_map.get(if_index)) or f"ifIndex-{if_index}"
        mask = _sanitize_text(ip_mask_map.get(suffix))
        key = (interface_name, ip_text, mask)

        if key in seen:
            continue
        seen.add(key)

        interfaces.append({
            "name": interface_name,
            "ip": ip_text,
            "mask": mask,
        })

    interfaces.sort(key=lambda item: (item["name"], item["ip"]))
    return interfaces


def _select_management_interface(legacy_interfaces):
    if not legacy_interfaces:
        return None

    def rank(item):
        name = _sanitize_text(item.get("name")).lower()
        ip_text = _safe_ip(item.get("ip"))
        mask = _sanitize_text(item.get("mask"))
        non_loopback = 1 if name and not name.startswith(("lo", "loopback", "tu", "tunnel")) else 0
        has_ip = 1 if ip_text else 0
        has_mask = 1 if mask else 0
        return (non_loopback, has_ip, has_mask)

    best = sorted(legacy_interfaces, key=rank, reverse=True)[0]
    if not _safe_ip(best.get("ip")):
        return None

    return {
        "name": "Management",
        "ip": _safe_ip(best.get("ip")),
        "mask": _sanitize_text(best.get("mask")),
    }


def _build_named_interfaces(interface_name_map, existing_interfaces):
    interfaces = list(existing_interfaces)
    names_with_ip_data = {
        item["name"]
        for item in interfaces
        if _sanitize_text(item.get("name")) and (_sanitize_text(item.get("ip")) or _sanitize_text(item.get("mask")))
    }
    seen = {(item["name"], item["ip"], item["mask"]) for item in interfaces}

    for if_index in sorted(interface_name_map, key=lambda value: int(value) if str(value).isdigit() else str(value)):
        interface_name = _sanitize_text(interface_name_map.get(if_index))
        if not interface_name:
            continue
        if interface_name in names_with_ip_data:
            continue

        key = (interface_name, "", "")
        if key in seen:
            continue
        seen.add(key)
        interfaces.append({
            "name": interface_name,
            "ip": "",
            "mask": "",
        })

    interfaces.sort(key=lambda item: (item["name"], item["ip"]))
    return interfaces


def _parse_ip_address_suffix(suffix):
    parts = [part for part in suffix.split(".") if part != ""]
    if not parts:
        return "", ""

    try:
        addr_type = int(parts[0])
    except ValueError:
        return "", ""

    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return ".".join(parts), "ipv4"

    if addr_type == 1:
        if len(parts) >= 6 and parts[1] == "4":
            return ".".join(parts[2:6]), "ipv4"
        if len(parts) >= 5:
            return ".".join(parts[1:5]), "ipv4"

    if addr_type == 2:
        octets = []
        if len(parts) >= 18 and parts[1] == "16":
            octets = parts[2:18]
        elif len(parts) >= 17:
            octets = parts[1:17]

        if octets:
            try:
                raw = bytes(int(part) for part in octets)
                return str(ipaddress.IPv6Address(raw)), "ipv6"
            except Exception:
                return "", ""

    return "", ""


def _prefix_pointer_to_mask(prefix_pointer):
    pointer_text = _sanitize_text(prefix_pointer)
    if not pointer_text or pointer_text == "0.0":
        return ""

    parts = [part for part in pointer_text.split(".") if part != ""]
    if not parts:
        return ""

    try:
        prefix_length = parts[-1]
        return _prefixlen_to_mask(prefix_length)
    except Exception:
        return ""


def _build_modern_ip_interfaces(interface_name_map, ip_address_ifindex_map, ip_address_prefix_map):
    interfaces = []
    seen = set()

    for suffix, if_index in ip_address_ifindex_map.items():
        ip_text, ip_family = _parse_ip_address_suffix(suffix)
        if ip_family != "ipv4" or not ip_text:
            continue

        if_index = _sanitize_text(if_index)
        if not if_index:
            continue

        interface_name = _sanitize_text(interface_name_map.get(if_index)) or f"ifIndex-{if_index}"
        mask = _prefix_pointer_to_mask(ip_address_prefix_map.get(suffix))
        key = (interface_name, ip_text, mask)
        if key in seen:
            continue
        seen.add(key)

        interfaces.append({
            "name": interface_name,
            "ip": ip_text,
            "mask": mask,
        })

    interfaces.sort(key=lambda item: (item["name"], item["ip"]))
    return interfaces


def _build_lldp_neighbors(lldp_local_ports, lldp_remote_names, lldp_remote_ports, lldp_remote_chassis):
    neighbors = []
    seen = set()

    for suffix in set(lldp_remote_names) | set(lldp_remote_chassis):
        suffix_parts = suffix.split(".")
        if len(suffix_parts) < 3:
            continue

        local_port_num = suffix_parts[-2]
        neighbor_hostname = _sanitize_text(lldp_remote_names.get(suffix)) or _sanitize_text(lldp_remote_chassis.get(suffix))
        remote_port = _sanitize_text(lldp_remote_ports.get(suffix))
        local_port = _sanitize_text(lldp_local_ports.get(local_port_num))

        if not neighbor_hostname or neighbor_hostname.startswith("0x"):
            continue

        entry = {
            "neighbor_hostname": neighbor_hostname,
            "neighbor_ip": "",
            "local_port": local_port or "Unknown",
            "remote_port": remote_port or "Unknown",
            "protocol": "LLDP",
        }
        key = tuple(entry.values())
        if key in seen:
            continue
        seen.add(key)
        neighbors.append(entry)

    return neighbors


def _decode_lldp_chassis_id(subtype, chassis_value):
    subtype_text = _sanitize_text(subtype).lower()
    chassis_text = _sanitize_text(chassis_value)
    if not chassis_text:
        return ""

    if subtype_text in {"4", "macAddress".lower(), "macaddress"}:
        raw_bytes = None
        if chassis_text.startswith("0x"):
            try:
                raw_bytes = bytes.fromhex(chassis_text[2:])
            except ValueError:
                raw_bytes = None
        elif re.fullmatch(r"[0-9a-fA-F]{12}", chassis_text):
            try:
                raw_bytes = bytes.fromhex(chassis_text)
            except ValueError:
                raw_bytes = None
        if raw_bytes:
            return _format_mac(raw_bytes)

    return chassis_text


def _build_lldp_mgmt_addr_map(lldp_remote_mgmt_addrs):
    mgmt_by_neighbor = {}
    for suffix, mgmt_addr in lldp_remote_mgmt_addrs.items():
        neighbor_index = _lldp_neighbor_index(suffix)
        if not neighbor_index:
            continue

        mgmt_ip = _safe_ip(mgmt_addr) or _parse_lldp_mgmt_ip_from_suffix(suffix)
        if mgmt_ip and neighbor_index not in mgmt_by_neighbor:
            mgmt_by_neighbor[neighbor_index] = mgmt_ip

    return mgmt_by_neighbor


def _parse_lldp_mgmt_ip_from_suffix(suffix):
    parts = [part for part in suffix.split(".") if part != ""]
    if len(parts) < 6:
        return ""

    try:
        addr_subtype = int(parts[3])
    except ValueError:
        return ""

    if addr_subtype == 1:
        if len(parts) >= 9 and parts[4] == "4":
            return _safe_ip(".".join(parts[5:9]))
        if len(parts) >= 8:
            return _safe_ip(".".join(parts[-4:]))

    if addr_subtype == 2:
        octets = []
        if len(parts) >= 21 and parts[4] == "16":
            octets = parts[5:21]
        elif len(parts) >= 19:
            octets = parts[-16:]

        if octets:
            try:
                raw = bytes(int(part) for part in octets)
                return str(ipaddress.IPv6Address(raw))
            except Exception:
                return ""

    return ""


def _build_enhanced_lldp_neighbors(
    lldp_local_ports,
    lldp_remote_names,
    lldp_remote_ports,
    lldp_remote_chassis_subtypes,
    lldp_remote_chassis,
    lldp_remote_mgmt_addrs,
):
    neighbors = []
    seen = set()
    mgmt_by_neighbor = _build_lldp_mgmt_addr_map(lldp_remote_mgmt_addrs)

    for suffix in set(lldp_remote_names) | set(lldp_remote_chassis):
        suffix_parts = [part for part in suffix.split(".") if part != ""]
        if len(suffix_parts) < 3:
            continue

        local_port_num = suffix_parts[1]
        neighbor_index = _lldp_neighbor_index(suffix)
        chassis_fallback = _decode_lldp_chassis_id(
            lldp_remote_chassis_subtypes.get(suffix),
            lldp_remote_chassis.get(suffix),
        )

        neighbor_hostname = _sanitize_text(lldp_remote_names.get(suffix)) or chassis_fallback
        remote_port = _sanitize_text(lldp_remote_ports.get(suffix))
        local_port = _sanitize_text(lldp_local_ports.get(local_port_num))
        neighbor_ip = mgmt_by_neighbor.get(neighbor_index, "")

        if not neighbor_hostname and not neighbor_ip:
            continue

        entry = {
            "neighbor_hostname": neighbor_hostname or "Unknown",
            "neighbor_ip": neighbor_ip or "Unknown",
            "local_port": local_port or "Unknown",
            "remote_port": remote_port or "Unknown",
            "protocol": "LLDP",
        }
        key = tuple(entry.values())
        if key in seen:
            continue
        seen.add(key)
        neighbors.append(entry)

    return neighbors


def _decode_cdp_address(value):
    text = _safe_ip(_snmp_value_to_text(value))
    if text:
        return text

    if hasattr(value, "asNumbers"):
        try:
            numbers = list(value.asNumbers())
            if numbers and len(numbers) >= 4:
                return _safe_ip(".".join(str(part) for part in numbers[-4:]))
        except Exception:
            pass

    return ""


def _decode_inet_address(value):
    text = _safe_ip(_snmp_value_to_text(value))
    if text:
        return text

    if hasattr(value, "asOctets"):
        try:
            raw = value.asOctets()
            if len(raw) == 4:
                return str(ipaddress.IPv4Address(raw))
            if len(raw) == 16:
                return str(ipaddress.IPv6Address(raw))
        except Exception:
            pass

    if hasattr(value, "asNumbers"):
        try:
            numbers = bytes(value.asNumbers())
            if len(numbers) == 4:
                return str(ipaddress.IPv4Address(numbers))
            if len(numbers) == 16:
                return str(ipaddress.IPv6Address(numbers))
        except Exception:
            pass

    return ""


def _build_cdp_neighbors(if_descr_map, cdp_names, cdp_ports, cdp_addrs):
    neighbors = []
    seen = set()

    for suffix, neighbor_hostname in cdp_names.items():
        suffix_parts = suffix.split(".")
        if len(suffix_parts) < 2:
            continue

        local_if_index = suffix_parts[0]
        local_port = _sanitize_text(if_descr_map.get(local_if_index)) or f"ifIndex-{local_if_index}"
        remote_port = _sanitize_text(cdp_ports.get(suffix))
        neighbor_ip = _sanitize_text(cdp_addrs.get(suffix))
        neighbor_hostname = _sanitize_text(neighbor_hostname)

        if not neighbor_hostname:
            continue

        entry = {
            "neighbor_hostname": neighbor_hostname,
            "neighbor_ip": neighbor_ip,
            "local_port": local_port or "Unknown",
            "remote_port": remote_port or "Unknown",
            "protocol": "CDP",
        }
        key = tuple(entry.values())
        if key in seen:
            continue
        seen.add(key)
        neighbors.append(entry)

    return neighbors


def _build_ip_only_neighbors(entries, protocol_name):
    neighbors = []
    seen = set()

    for value in entries.values():
        ip_text = _safe_ip(value)
        if not ip_text:
            continue

        entry = {
            "neighbor_hostname": "",
            "neighbor_ip": ip_text,
            "local_port": "Unknown",
            "remote_port": "Unknown",
            "protocol": protocol_name,
        }
        key = tuple(entry.values())
        if key in seen:
            continue
        seen.add(key)
        neighbors.append(entry)

    return neighbors


def _build_bgp_neighbors(entries, states, protocol_name):
    neighbors = []
    seen = set()
    fallback_candidates = []

    for suffix, value in entries.items():
        state = _sanitize_text(states.get(suffix))

        ip_text = _safe_ip(value)
        if not ip_text:
            ip_text, _ = _parse_ip_address_suffix(suffix)
            ip_text = _safe_ip(ip_text)
        if not ip_text:
            continue

        if state and not _is_established_bgp_state(state):
            fallback_candidates.append(ip_text)
            continue

        entry = {
            "neighbor_hostname": "",
            "neighbor_ip": ip_text,
            "local_port": "Unknown",
            "remote_port": "Unknown",
            "protocol": protocol_name,
        }
        key = tuple(entry.values())
        if key in seen:
            continue
        seen.add(key)
        neighbors.append(entry)

    if not neighbors:
        for ip_text in fallback_candidates:
            entry = {
                "neighbor_hostname": "",
                "neighbor_ip": ip_text,
                "local_port": "Unknown",
                "remote_port": "Unknown",
                "protocol": protocol_name,
            }
            key = tuple(entry.values())
            if key in seen:
                continue
            seen.add(key)
            neighbors.append(entry)

    return neighbors


def _is_established_bgp_state(state):
    state_text = _sanitize_text(state).lower()
    if not state_text:
        return False

    if state_text in {"6", "established"}:
        return True

    match = re.search(r"\b(\d+)\b", state_text)
    if match and match.group(1) == "6":
        return True

    return "established" in state_text


def _normalize_neighbors(neighbors):
    normalized = []
    seen = set()

    for neighbor in neighbors:
        neighbor_hostname = _sanitize_text(neighbor.get("neighbor_hostname")) or "Unknown"
        neighbor_ip = _safe_ip(neighbor.get("neighbor_ip")) or "Unknown"
        local_port = _sanitize_text(neighbor.get("local_port")) or "Unknown"
        remote_port = _sanitize_text(neighbor.get("remote_port")) or "Unknown"
        protocol = _sanitize_text(neighbor.get("protocol")) or "Unknown"

        if neighbor_hostname == "Unknown" and neighbor_ip == "Unknown":
            continue

        key = (neighbor_hostname, neighbor_ip, local_port, remote_port, protocol)
        if key in seen:
            continue
        seen.add(key)

        normalized.append({
            "neighbor_hostname": neighbor_hostname,
            "neighbor_ip": neighbor_ip,
            "local_port": local_port,
            "remote_port": remote_port,
            "protocol": protocol,
        })

    normalized.sort(key=lambda item: (item["protocol"], item["neighbor_hostname"], item["neighbor_ip"]))
    return normalized


def _raw_snmp_error_detail(error_indication=None, error_status=None, error_index=None):
    detail_parts = []

    if error_indication:
        detail_parts.append(str(error_indication))

    if error_status:
        status_text = error_status.prettyPrint() if hasattr(error_status, "prettyPrint") else str(error_status)
        if status_text:
            detail_parts.append(status_text)

    if error_index:
        detail_parts.append(f"index={error_index}")

    return " | ".join(part for part in detail_parts if part)


def _classify_snmp_error(error_indication=None, error_status=None, error_index=None):
    detail = _raw_snmp_error_detail(error_indication, error_status, error_index)
    detail_lower = detail.lower()

    if not detail:
        return "snmp_error", ""

    if "no snmp response received before timeout" in detail_lower or "requesttimedout" in detail_lower:
        return "no_snmp_response", detail

    credential_markers = (
        "unknown usm user",
        "unknownusername",
        "unknown user",
        "unknownsecurityname",
        "wrongdigest",
        "wrong digest",
        "decryptionerror",
        "decryption error",
        "unsupportedsecuritylevel",
        "unsupported security level",
        "notintimewindow",
        "not in time window",
        "authorizationerror",
        "authorization error",
        "authenticationfailure",
        "authentication failure",
        "unknownengineid",
        "unknown engine id",
    )
    if any(marker in detail_lower for marker in credential_markers):
        return "no_valid_keys", detail

    if "nosuchname" in detail_lower:
        return "oid_not_supported", detail

    return "snmp_error", detail


def _error_response(error_indication=None, error_status=None, error_index=None):
    reason, detail = _classify_snmp_error(error_indication, error_status, error_index)
    response = {"status": "error", "reason": reason}
    if detail:
        response["detail"] = detail
    return response


async def fetch_inventory(ip_address: str, snmp_params: dict):
    timeout = int(os.environ.get("SCANNER_SNMP_TIMEOUT", 2))
    retries = int(os.environ.get("SCANNER_SNMP_RETRIES", 1))

    if snmp_params.get("version") in ["2", "2c"]:
        auth_data = CommunityData(snmp_params.get("community"), mpModel=1)
    elif snmp_params.get("version") == "3":
        auth_proto = usmNoAuthProtocol
        if snmp_params.get("auth_key"):
            auth_proto = usmHMACSHAAuthProtocol
            if snmp_params.get("auth_protocol", "").upper() == "MD5":
                auth_proto = usmHMACMD5AuthProtocol

        priv_proto = usmNoPrivProtocol
        if snmp_params.get("priv_key"):
            priv_proto = usmAesCfb128Protocol
            if snmp_params.get("priv_protocol", "").upper() == "DES":
                priv_proto = usmDESPrivProtocol

        try:
            auth_data = UsmUserData(
                userName=snmp_params.get("username"),
                authKey=snmp_params.get("auth_key"),
                privKey=snmp_params.get("priv_key"),
                authProtocol=auth_proto,
                privProtocol=priv_proto,
            )
        except Exception as exc:
            return {"status": "error", "reason": f"invalid_v3_creds: {exc}"}
    else:
        return {"status": "error", "reason": "unsupported_snmp_version"}

    engine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create((ip_address, 161), timeout=timeout, retries=retries)
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}

    try:
        error_indication, error_status, error_index, var_binds = await get_cmd(
            engine,
            auth_data,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(SYS_DESCR_OID)),
            ObjectType(ObjectIdentity(SYS_OBJECT_ID_OID)),
            ObjectType(ObjectIdentity(SYS_UPTIME_OID)),
            ObjectType(ObjectIdentity(SYS_NAME_OID)),
        )
    except Exception as exc:
        if getattr(engine, "transportDispatcher", None):
            engine.transportDispatcher.closeDispatcher()
        return {"status": "error", "reason": str(exc)}

    if error_indication or error_status:
        if getattr(engine, "transportDispatcher", None):
            engine.transportDispatcher.closeDispatcher()
        return _error_response(error_indication, error_status, error_index)

    sys_values = {}
    for oid, value in var_binds:
        sys_values[str(oid)] = _snmp_value_to_text(value)

    inventory = _parse_sysdescr(
        sys_values.get(SYS_DESCR_OID, ""),
        sys_values.get(SYS_OBJECT_ID_OID, ""),
    )
    inventory["hostname"] = _sanitize_text(sys_values.get(SYS_NAME_OID, ""))

    uptime_raw = _sanitize_text(sys_values.get(SYS_UPTIME_OID, "0"))
    try:
        inventory["uptime_seconds"] = int(float(uptime_raw)) // 100
    except ValueError:
        inventory["uptime_seconds"] = 0

    try:
        (
            if_descr_map,
            if_name_map,
            ip_addr_map,
            ip_mask_map,
            ip_ifindex_map,
            ip_address_ifindex_map,
            ip_address_prefix_map,
        ) = await asyncio.gather(
            _walk_single_map(engine, auth_data, transport, IF_DESCR_OID),
            _walk_single_map(engine, auth_data, transport, IF_NAME_OID),
            _walk_single_map(engine, auth_data, transport, IP_ADDR_OID, transform=_decode_ipv4_like_value),
            _walk_single_map(engine, auth_data, transport, IP_NETMASK_OID, transform=_decode_ipv4_like_value),
            _walk_single_map(engine, auth_data, transport, IP_IFINDEX_OID),
            _walk_single_map(engine, auth_data, transport, IP_ADDRESS_IFINDEX_OID),
            _walk_single_map(engine, auth_data, transport, IP_ADDRESS_PREFIX_OID),
        )
        interface_name_map = dict(if_name_map)
        for if_index, if_descr in if_descr_map.items():
            interface_name_map.setdefault(if_index, if_descr)
        if_descr_map = interface_name_map

        legacy_interfaces = _build_interfaces(interface_name_map, ip_addr_map, ip_mask_map, ip_ifindex_map)
        modern_interfaces = _build_modern_ip_interfaces(interface_name_map, ip_address_ifindex_map, ip_address_prefix_map)
        management_interface = _select_management_interface(legacy_interfaces)

        if modern_interfaces:
            interfaces = list(modern_interfaces)
        elif len(legacy_interfaces) > 1:
            interfaces = list(legacy_interfaces)
        else:
            interfaces = []

        existing_keys = {(item["name"], item["ip"], item["mask"]) for item in interfaces}
        for item in modern_interfaces:
            key = (item["name"], item["ip"], item["mask"])
            if key not in existing_keys:
                existing_keys.add(key)
                interfaces.append(item)
        interfaces = _build_named_interfaces(interface_name_map, interfaces)
        if management_interface:
            management_ip = management_interface["ip"]
            if management_ip and all(item.get("ip") != management_ip for item in interfaces):
                interfaces.append(management_interface)
        interfaces.sort(key=lambda item: (item["name"], item["ip"]))
    except Exception:
        if_descr_map = {}
        interfaces = []

    try:
        (
            ent_classes,
            ent_names,
            ent_model_names,
            ent_descrs,
            ent_hw_revs,
            ent_sw_revs,
            ent_serials,
        ) = await asyncio.gather(
            _walk_single_map(engine, auth_data, transport, ENT_PHYSICAL_CLASS_OID),
            _walk_single_map(engine, auth_data, transport, ENT_PHYSICAL_NAME_OID),
            _walk_single_map(engine, auth_data, transport, ENT_PHYSICAL_MODEL_NAME_OID),
            _walk_single_map(engine, auth_data, transport, ENT_PHYSICAL_DESCR_OID),
            _walk_single_map(engine, auth_data, transport, ENT_PHYSICAL_HARDWARE_REV_OID),
            _walk_single_map(engine, auth_data, transport, ENT_PHYSICAL_SOFTWARE_REV_OID),
            _walk_single_map(engine, auth_data, transport, ENT_PHYSICAL_SERIAL_NUM_OID),
        )
        inventory = _merge_entity_inventory(
            inventory,
            ent_classes,
            ent_names,
            ent_model_names,
            ent_descrs,
            ent_hw_revs,
            ent_sw_revs,
            ent_serials,
        )
    except Exception:
        pass

    neighbors = []
    try:
        (
            lldp_local_ports,
            lldp_remote_names,
            lldp_remote_ports,
            lldp_remote_chassis_subtypes,
            lldp_remote_chassis,
            lldp_remote_mgmt_addrs,
            cdp_names,
            cdp_ports,
            cdp_addrs,
            bgp_neighbors,
            bgp_states,
            cbgp2_neighbors,
            cbgp2_states,
            ospf_neighbors,
        ) = await asyncio.gather(
            _walk_single_map(engine, auth_data, transport, LLDP_LOC_PORT_DESC_OID),
            _walk_single_map(engine, auth_data, transport, LLDP_REM_SYS_NAME_OID),
            _walk_single_map(engine, auth_data, transport, LLDP_REM_PORT_DESC_OID),
            _walk_single_map(engine, auth_data, transport, LLDP_REM_CHASSIS_ID_SUBTYPE_OID),
            _walk_single_map(engine, auth_data, transport, LLDP_REM_CHASSIS_ID_OID, transform=_snmp_value_to_hex_or_text),
            _walk_single_map(engine, auth_data, transport, LLDP_REM_MAN_ADDR_OID, transform=_decode_inet_address),
            _walk_single_map(engine, auth_data, transport, CDP_CACHE_DEVICE_ID_OID),
            _walk_single_map(engine, auth_data, transport, CDP_CACHE_DEVICE_PORT_OID),
            _walk_single_map(engine, auth_data, transport, CDP_CACHE_ADDRESS_OID, transform=_decode_cdp_address),
            _walk_single_map(engine, auth_data, transport, BGP_PEER_REMOTE_ADDR_OID, transform=_decode_ipv4_like_value),
            _walk_single_map(engine, auth_data, transport, BGP_PEER_STATE_OID),
            _walk_single_map(engine, auth_data, transport, CBGP_PEER2_REMOTE_ADDR_OID, transform=_decode_inet_address),
            _walk_single_map(engine, auth_data, transport, CBGP_PEER2_STATE_OID),
            _walk_single_map(engine, auth_data, transport, OSPF_NBR_IP_ADDR_OID),
        )

        neighbors.extend(_build_enhanced_lldp_neighbors(
            lldp_local_ports,
            lldp_remote_names,
            lldp_remote_ports,
            lldp_remote_chassis_subtypes,
            lldp_remote_chassis,
            lldp_remote_mgmt_addrs,
        ))
        neighbors.extend(_build_cdp_neighbors(if_descr_map, cdp_names, cdp_ports, cdp_addrs))
        neighbors.extend(_build_bgp_neighbors(bgp_neighbors, bgp_states, "BGP"))
        neighbors.extend(_build_bgp_neighbors(cbgp2_neighbors, cbgp2_states, "BGP"))
        neighbors.extend(_build_ip_only_neighbors(ospf_neighbors, "OSPF"))
        neighbors = _normalize_neighbors(neighbors)
    except Exception:
        neighbors = _normalize_neighbors(neighbors)

    if getattr(engine, "transportDispatcher", None):
        engine.transportDispatcher.closeDispatcher()

    return {
        "status": "success",
        "inventory": inventory,
        "interfaces": interfaces,
        "neighbors": neighbors,
    }


def get_inventory(ip_address: str, snmp_params: dict) -> dict:
    return asyncio.run(fetch_inventory(ip_address, snmp_params))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone SNMP Component")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--version", choices=["2c", "3"], required=True)
    parser.add_argument("--community", help="SNMPv2c Community")
    parser.add_argument("--v3-user")
    parser.add_argument("--v3-auth")
    parser.add_argument("--v3-priv")

    args = parser.parse_args()

    params = {"version": args.version}
    if args.version == "2c":
        params["community"] = args.community
    else:
        params["username"] = args.v3_user
        params["auth_key"] = args.v3_auth
        params["priv_key"] = args.v3_priv

    res = get_inventory(args.ip, params)
    print(json.dumps(res, indent=2))
