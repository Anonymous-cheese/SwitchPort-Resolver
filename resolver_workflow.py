"""Pure resolver view, input-report, and explicit-session helpers."""

import ipaddress
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SESSION_FORMAT = "switchport-resolver-session"
SESSION_VERSION = 1
MAX_INPUT_CHARS = 5_000_000
RESULT_COLUMNS = ("switch", "vlan", "iface", "mac", "vendor", "ip", "router", "arp_iface")


def is_current_lookup_result(result, generation, inputs):
    """A queued worker result is usable only for the latest unchanged request."""
    return result.get("generation") == generation and result.get("inputs") == inputs


def _natural(value):
    return tuple((0, int(part)) if part.isdigit() else (1, part.casefold())
                 for part in re.split(r"(\d+)", str(value or "")))


def filter_sort_rows(rows, query="", ip_filter="All rows", sort_column="switch", descending=False):
    needle = query.strip().casefold()
    filtered = [row for row in rows if
                (not needle or any(needle in str(value).casefold() for value in row)) and
                (ip_filter == "All rows" or (bool(str(row[5]).strip()) == (ip_filter == "Has IP")))]
    column = RESULT_COLUMNS.index(sort_column) if sort_column in RESULT_COLUMNS else 0

    def key(row):
        value = row[column]
        if sort_column == "vlan":
            try:
                return (0, int(value))
            except (TypeError, ValueError):
                return (1, _natural(value))
        if sort_column == "ip":
            try:
                return (0, int(ipaddress.ip_address(value)))
            except (TypeError, ValueError):
                return (1, _natural(value))
        return _natural(value)

    return sorted(filtered, key=key, reverse=descending)


def _mac_key(value):
    chars = re.sub(r"[^0-9A-Fa-f]", "", value or "").upper()
    return chars if len(chars) == 12 else ""


def build_input_report(switch_inputs, router_inputs, parse_mac, parse_arp,
                       exclude_po=True, exclude_cpu=True):
    """Report parser yield and correlation without retaining or exposing source text."""
    devices = []
    arp_keys = set()
    arp_total = 0
    for slot, item in enumerate(router_inputs, 1):
        raw = (item.get("text") or "").strip()
        if not raw:
            continue
        parsed = parse_arp(raw)
        arp_total += len(parsed)
        arp_keys.update(key for _, mac, _ in parsed if (key := _mac_key(mac)))
        devices.append({"kind": "Router", "slot": slot, "name": item.get("name") or f"RT{slot}",
                        "parsed": len(parsed), "eligible": len(parsed), "excluded": 0,
                        "matched": 0, "unmatched": 0,
                        "warning": "No ARP entries recognized" if not parsed else ""})

    mac_total = eligible_total = excluded_total = matched_total = 0
    for slot, item in enumerate(switch_inputs, 1):
        raw = (item.get("text") or "").strip()
        if not raw:
            continue
        parsed = parse_mac(raw)
        excluded = sum(bool(exclude_po and iface.startswith("Po")) or
                       bool(exclude_cpu and iface.upper() == "CPU") for _, _, _, iface in parsed)
        eligible = [entry for entry in parsed if not
                    ((exclude_po and entry[3].startswith("Po")) or
                     (exclude_cpu and entry[3].upper() == "CPU"))]
        matched = sum(_mac_key(mac) in arp_keys for _, mac, _, _ in eligible)
        mac_total += len(parsed)
        eligible_total += len(eligible)
        excluded_total += excluded
        matched_total += matched
        warning = ""
        if not parsed:
            warning = "No MAC entries recognized"
        elif not eligible:
            warning = "All MAC entries excluded by settings"
        elif arp_keys and not matched:
            warning = "No MACs matched router ARP entries"
        devices.append({"kind": "Switch", "slot": slot, "name": item.get("name") or f"SW{slot}",
                        "parsed": len(parsed), "eligible": len(eligible), "excluded": excluded,
                        "matched": matched, "unmatched": len(eligible) - matched,
                        "warning": warning})
    if eligible_total and not arp_keys:
        devices.append({"kind": "Notice", "slot": 0, "name": "ARP data",
                        "parsed": 0, "eligible": 0, "excluded": 0, "matched": 0,
                        "unmatched": 0, "warning": "",
                        "notice": "No router ARP entries; MAC-only results are available"})
    return {"devices": devices, "mac_parsed": mac_total, "mac_eligible": eligible_total,
            "mac_excluded": excluded_total, "arp_parsed": arp_total,
            "mac_matched": matched_total, "mac_unmatched": eligible_total - matched_total,
            "warnings": sum(bool(device["warning"]) for device in devices)}


def make_session(switch_inputs, router_inputs):
    return {"format": SESSION_FORMAT, "version": SESSION_VERSION,
            "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "switches": [{"name": item["name"], "text": item["text"]} for item in switch_inputs],
            "routers": [{"name": item["name"], "text": item["text"]} for item in router_inputs]}


def validate_session(data):
    if not isinstance(data, dict) or data.get("format") != SESSION_FORMAT or data.get("version") != SESSION_VERSION:
        raise ValueError("This is not a supported SwitchPort Resolver session.")
    for key, maximum in (("switches", 5), ("routers", 2)):
        items = data.get(key)
        if not isinstance(items, list) or len(items) != maximum:
            raise ValueError(f"Session must have {maximum} {key} slots.")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("text"), str):
                raise ValueError(f"Invalid {key} entry in session.")
            if len(item["name"]) > 200 or len(item["text"]) > MAX_INPUT_CHARS:
                raise ValueError("Session contains an oversized input.")
    return data


def read_session(path):
    with open(path, "r", encoding="utf-8") as stream:
        return validate_session(json.load(stream))


def write_session(path, switch_inputs, router_inputs):
    data = validate_session(make_session(switch_inputs, router_inputs))
    target = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent,
                                         prefix="session-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(data, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, target)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
