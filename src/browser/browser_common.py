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

import os
import re
from datetime import datetime
from functools import lru_cache


VENDOR_COLORS = {
    "Cisco": "#1f77b4",
    "Juniper": "#2ca02c",
    "Arista": "#9467bd",
    "Palo Alto": "#d62728",
    "Unknown": "#aaaaaa",
}

VENDOR_LOGO_FILES = {
    "Cisco": "cisco.png",
    "Juniper": "juniper.png",
    "Arista": "arista.png",
    "Palo Alto": "palo-alto.png",
    "Unknown": "unknown.png",
}

DEVICE_TYPE_SHAPES = {
    "Router": "circle",
    "Switch": "square",
    "Firewall": "diamond",
    "Unknown": "rounded",
}


def normalize_vendor(*values):
    haystack = " ".join(str(value or "") for value in values).lower()

    vendor_signatures = (
        ("Palo Alto", ("palo alto", "pan-os", "pa-")),
        ("Cisco", ("cisco", "ios xe", "ios-xe", "ios software", "catalyst", "nexus", "c8000", "csr", "isr", "asr", "ws-c")),
        ("Juniper", ("juniper", "junos", "qfx", "mx", "srx", "ex2200", "ex2300", "ex3400", "ex4300", "ex4600")),
        ("Arista", ("arista", "eos", "dcs-")),
    )

    for vendor, signatures in vendor_signatures:
        if any(signature in haystack for signature in signatures):
            return vendor

    return "Unknown"


def infer_device_type(hostname="", vendor="", model="", hardware_product="", software_image=""):
    haystack = " ".join(
        str(value or "") for value in (hostname, vendor, model, hardware_product, software_image)
    ).lower()

    if any(token in haystack for token in ("firewall", "pan-os", "pa-", "asa", "firepower", "ftd", "srx")):
        return "Firewall"

    if any(token in haystack for token in ("router", "isr", "asr", "csr", "c8000", "mx", "wan edge")):
        return "Router"

    return "Switch"


@lru_cache(maxsize=32)
def _build_evidence_index(target_dir):
    relative_map = {}
    basename_map = {}

    if not target_dir or not os.path.isdir(target_dir):
        return relative_map, basename_map

    for root, _, files in os.walk(target_dir):
        for filename in files:
            full_path = os.path.join(root, filename)
            relative_path = os.path.relpath(full_path, target_dir).replace("\\", "/").lower()
            relative_map[relative_path] = full_path
            basename_map.setdefault(filename.lower(), []).append(full_path)

    for matches in basename_map.values():
        matches.sort()

    return relative_map, basename_map


def resolve_evidence_path(target_dir, evidence_file_path):
    if not target_dir or not evidence_file_path:
        return None

    raw_value = str(evidence_file_path).strip()
    if not raw_value:
        return None

    normalized = os.path.normpath(raw_value)
    if os.path.isabs(normalized) and os.path.exists(normalized):
        return normalized

    direct_candidate = os.path.normpath(os.path.join(target_dir, normalized))
    if os.path.exists(direct_candidate):
        return direct_candidate

    relative_map, basename_map = _build_evidence_index(os.path.abspath(target_dir))
    relative_key = normalized.replace("\\", "/").lstrip("./").lower()

    if relative_key in relative_map:
        return relative_map[relative_key]

    basename = os.path.basename(normalized).lower()
    matches = basename_map.get(basename, [])
    if matches:
        return matches[0]

    return None


def extract_scan_time(evidence_file_path="", fallback=None):
    raw_value = str(evidence_file_path or "")

    timestamp_patterns = (
        r"(\d{8}_\d{6})",
        r"(\d{8}-\d{6})",
    )

    for pattern in timestamp_patterns:
        match = re.search(pattern, raw_value)
        if not match:
            continue

        raw_timestamp = match.group(1).replace("-", "_")
        try:
            parsed = datetime.strptime(raw_timestamp, "%Y%m%d_%H%M%S")
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    return fallback or "Unknown"


def normalize_logo_assets(static_root, canvas_size=64, content_size=40):
    logos_dir = os.path.join(static_root, "logos")
    if not os.path.isdir(logos_dir):
        return

    source_dir_candidates = (
        os.path.join(static_root, "logos_src"),
        os.path.join(static_root, "logo_sources"),
        logos_dir,
    )
    source_dir = next((path for path in source_dir_candidates if os.path.isdir(path)), logos_dir)
    display_dir = os.path.join(static_root, "logos_display")
    os.makedirs(display_dir, exist_ok=True)

    try:
        from PIL import Image, ImageDraw
    except ImportError as exc:
        raise RuntimeError(
            "Logo normalization requires Pillow. Install it with `pip install pillow`."
        ) from exc

    resampling_attr = getattr(Image, "Resampling", None)
    resample_mode = resampling_attr.LANCZOS if resampling_attr else Image.LANCZOS
    reverse_logo_lookup = {filename: vendor for vendor, filename in VENDOR_LOGO_FILES.items()}

    def draw_shape(draw, shape_name, bounds, fill, outline):
        inset = 3
        x0, y0, x1, y1 = bounds
        style = {"fill": fill}
        if outline is not None:
            style["outline"] = outline
            style["width"] = 2
        if shape_name == "circle":
            draw.ellipse((x0 + inset, y0 + inset, x1 - inset, y1 - inset), **style)
            return
        if shape_name == "diamond":
            cx = (x0 + x1) / 2
            cy = (y0 + y1) / 2
            draw.polygon(
                [
                    (cx, y0 + inset),
                    (x1 - inset, cy),
                    (cx, y1 - inset),
                    (x0 + inset, cy),
                ],
                **style,
            )
            return
        if shape_name == "rounded":
            draw.rounded_rectangle((x0 + inset, y0 + inset, x1 - inset, y1 - inset), radius=12, **style)
            return
        draw.rectangle((x0 + inset, y0 + inset, x1 - inset, y1 - inset), **style)

    for filename in os.listdir(source_dir):
        if not filename.lower().endswith(".png"):
            continue

        source_path = os.path.join(source_dir, filename)

        with Image.open(source_path) as img:
            normalized = img.convert("RGBA")
            normalized.thumbnail((content_size, content_size), resample_mode)

        vendor_name = reverse_logo_lookup.get(filename, "Unknown")
        border_hex = VENDOR_COLORS.get(vendor_name, VENDOR_COLORS["Unknown"])
        border_rgb = tuple(int(border_hex[index:index + 2], 16) for index in (1, 3, 5))
        shape_fill = (255, 255, 255, 255)
        shape_outline = (*border_rgb, 255)

        for shape_name in {"circle", "square", "diamond", "rounded"}:
            display = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
            mask = Image.new("L", (canvas_size, canvas_size), 0)
            mask_draw = ImageDraw.Draw(mask)
            draw_shape(mask_draw, shape_name, (0, 0, canvas_size - 1, canvas_size - 1), 255, None)

            background = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
            background_draw = ImageDraw.Draw(background)
            draw_shape(background_draw, shape_name, (0, 0, canvas_size - 1, canvas_size - 1), shape_fill, shape_outline)

            icon_layer = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
            x_offset = (canvas_size - normalized.width) // 2
            y_offset = (canvas_size - normalized.height) // 2
            icon_layer.paste(normalized, (x_offset, y_offset), normalized)

            composed = Image.alpha_composite(background, icon_layer)
            display.paste(composed, (0, 0), mask)
            display_path = os.path.join(display_dir, f"{os.path.splitext(filename)[0]}-{shape_name}.png")
            display.save(display_path, format="PNG")


def get_display_logo_filename(vendor, device_type):
    base_filename = VENDOR_LOGO_FILES.get(vendor, VENDOR_LOGO_FILES["Unknown"])
    base_name, _ = os.path.splitext(base_filename)
    shape_name = DEVICE_TYPE_SHAPES.get(device_type, DEVICE_TYPE_SHAPES["Unknown"])
    return f"{base_name}-{shape_name}.png"
