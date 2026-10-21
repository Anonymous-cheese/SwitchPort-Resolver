"""Offline network calculations used by the Tools workspace."""

import ipaddress
import re


def ipv4_class(address):
    first = int(str(address).split(".")[0])
    if first < 128:
        return "A", 8
    if first < 192:
        return "B", 16
    if first < 224:
        return "C", 24
    if first < 240:
        return "D (multicast)", None
    return "E (reserved)", None


def ipv4_details(address_text, mask_text="24"):
    """Accept CIDR, a prefix, or a dotted mask; retain the supplied host."""
    address_text = address_text.strip()
    if "/" in address_text:
        address_text, mask_text = address_text.split("/", 1)
    address = ipaddress.IPv4Address(address_text.strip())
    mask_text = str(mask_text).strip().lstrip("/")
    if not mask_text:
        raise ValueError("Enter a prefix length or subnet mask.")
    network = ipaddress.IPv4Network(f"{address}/{mask_text}", strict=False)
    prefix = network.prefixlen
    count = network.num_addresses
    if prefix == 32:
        first = last = network.network_address
        usable = 1
    elif prefix == 31:
        first, last = network.network_address, network.broadcast_address
        usable = 2
    else:
        first = network.network_address + 1
        last = network.broadcast_address - 1
        usable = count - 2
    address_class, class_prefix = ipv4_class(address)
    subnet_bits = max(0, prefix - class_prefix) if class_prefix is not None else None
    return {
        "address": address,
        "network": network,
        "class": address_class,
        "prefix": prefix,
        "mask": network.netmask,
        "wildcard": network.hostmask,
        "subnet_bits": subnet_bits,
        "max_subnets": 2 ** subnet_bits if subnet_bits is not None else None,
        "host_bits": 32 - prefix,
        "total": count,
        "usable": usable,
        "first": first,
        "last": last,
        "broadcast": network.broadcast_address,
        "previous": ipaddress.IPv4Address(int(network.network_address) - count)
        if int(network.network_address) >= count else None,
        "next": ipaddress.IPv4Address(int(network.network_address) + count)
        if int(network.network_address) + count < 2 ** 32 else None,
    }


def ipv4_binary(address):
    return " ".join(f"{int(octet):08b}" for octet in str(address).split("."))


def ipv6_details(address_text, prefix_text="64"):
    address_text = address_text.strip()
    if "/" in address_text:
        address_text, prefix_text = address_text.split("/", 1)
    address = ipaddress.IPv6Address(address_text.strip())
    prefix = int(str(prefix_text).strip().lstrip("/"))
    network = ipaddress.IPv6Network((address, prefix), strict=False)
    size = network.num_addresses
    start = network.network_address
    end = ipaddress.IPv6Address(int(start) + size - 1)
    if address.is_unspecified:
        address_type = "unspecified"
    elif address.is_loopback:
        address_type = "loopback"
    elif address.is_multicast:
        address_type = "multicast"
    elif address.is_link_local:
        address_type = "link local"
    elif address in ipaddress.IPv6Network("2001:db8::/32"):
        address_type = "documentation"
    elif address in ipaddress.IPv6Network("fc00::/7"):
        address_type = "unique local"
    elif address.is_private:
        address_type = "non-global"
    else:
        address_type = "global"
    return {
        "address": address,
        "expanded": address.exploded,
        "network": network,
        "prefix": prefix,
        "prefix_mask": network.netmask,
        "host_bits": 128 - prefix,
        "total": size,
        "first": start,
        "last": end,
        "type": address_type,
        "previous": ipaddress.IPv6Address(int(start) - size)
        if int(start) >= size else None,
        "next": ipaddress.IPv6Address(int(start) + size)
        if int(start) + size < 2 ** 128 else None,
    }


def ipv6_subnet_page(network, child_prefix, page=0, page_size=8):
    """Return a bounded page of child networks without enumerating huge ranges."""
    if not isinstance(network, ipaddress.IPv6Network):
        network = ipaddress.IPv6Network(network, strict=False)
    child_prefix = int(child_prefix)
    if not network.prefixlen <= child_prefix <= 128:
        raise ValueError(f"Child prefix must be between /{network.prefixlen} and /128.")
    count = 1 << (child_prefix - network.prefixlen)
    pages = (count + page_size - 1) // page_size
    if not 0 <= page < pages:
        raise ValueError("Subnet page is out of range.")
    size = 1 << (128 - child_prefix)
    first_index = page * page_size
    rows = []
    for index in range(first_index, min(first_index + page_size, count)):
        address = ipaddress.IPv6Address(int(network.network_address) + index * size)
        rows.append((index + 1, ipaddress.IPv6Network((address, child_prefix))))
    return {"count": count, "pages": pages, "page": page, "rows": rows}


def ipv6_binary(address):
    bits = f"{int(address):0128b}"
    return " ".join(bits[i:i + 16] for i in range(0, 128, 16))


def wildcard_details(address_text, wildcard_text, candidate_text=""):
    """Cisco wildcard semantics: 0 bits must match; 1 bits are ignored."""
    address = ipaddress.IPv4Address(address_text.strip())
    wildcard = ipaddress.IPv4Address(wildcard_text.strip())
    mask = ipaddress.IPv4Address((2 ** 32 - 1) ^ int(wildcard))
    base = ipaddress.IPv4Address(int(address) & int(mask))
    upper = ipaddress.IPv4Address(int(base) | int(wildcard))
    candidate = ipaddress.IPv4Address(candidate_text.strip()) if candidate_text.strip() else None
    matched = (int(candidate) & int(mask)) == int(base) if candidate is not None else None
    try:
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ipaddress.NetmaskValueError:
        prefix = None
    return {
        "address": address, "wildcard": wildcard, "mask": mask,
        "base": base, "upper": upper, "count": 2 ** int(wildcard).bit_count(),
        "prefix": prefix, "candidate": candidate, "matched": matched,
    }


def decimal_ip_details(value):
    """Convert IPv4 dotted decimal, unsigned integer, or 0x hexadecimal."""
    value = value.strip()
    if "." in value:
        address = ipaddress.IPv4Address(value)
    elif value.lower().startswith("0x"):
        address = ipaddress.IPv4Address(int(value, 16))
    elif re.fullmatch(r"\d+", value):
        address = ipaddress.IPv4Address(int(value, 10))
    else:
        raise ValueError("Enter an IPv4 address, unsigned integer, or 0x hexadecimal value.")
    return {
        "address": address,
        "integer": int(address),
        "hex": f"0x{int(address):08X}",
        "binary": ipv4_binary(address),
    }


def mac_details(value, vendor_lookup):
    """Normalize one 48-bit MAC address and reuse the app's OUI lookup."""
    value = value.strip()
    if not re.fullmatch(
        r"(?:[0-9a-fA-F]{12}|[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}|"
        r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|"
        r"[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", value,
    ):
        raise ValueError("Enter a complete 12-digit MAC address.")
    raw = re.sub(r"[^0-9a-fA-F]", "", value).upper()
    first_byte = int(raw[:2], 16)
    return {
        "input": value,
        "cisco": ".".join(raw[i:i + 4] for i in range(0, 12, 4)),
        "colon": ":".join(raw[i:i + 2] for i in range(0, 12, 2)),
        "colon_lower": ":".join(raw[i:i + 2] for i in range(0, 12, 2)).lower(),
        "hyphen": "-".join(raw[i:i + 2] for i in range(0, 12, 2)),
        "plain": raw,
        "oui": ":".join(raw[i:i + 2] for i in range(0, 6, 2)),
        "vendor": vendor_lookup(raw) or "Unknown / not in local database",
        "assignment": "Locally administered" if first_byte & 2 else "Universally administered",
        "delivery": "Multicast" if first_byte & 1 else "Unicast",
    }
