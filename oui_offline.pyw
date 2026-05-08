import os
import sys
import re
import csv
import threading
import urllib.request
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
CACHE_DIR = os.path.join(Path.home(), ".oui_lookup")
CACHE_FILE = os.path.join(CACHE_DIR, "manuf")
APP_NAME = "SwitchPort Resolver"
APP_VERSION = "2.2"
DEVELOPER_NAME = "Philip Cartier"
DEVELOPER_TAG = "746f617374"

# ---------------------------------------------------------------------------
# Utility: bundled path helper for PyInstaller
# ---------------------------------------------------------------------------

def get_bundled_path(name: str) -> str:
    # Return an absolute path to a bundled resource (PyInstaller-compatible).
    # When not frozen, this falls back to the script directory.
    if hasattr(sys, "_MEIPASS"):
        # When running from a PyInstaller one-file EXE
        return os.path.join(sys._MEIPASS, name)
    # Normal Python run (not frozen)
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(exe_dir, name)

# ---------------------------------------------------------------------------
# Utility: MAC normalization / formatting
# ---------------------------------------------------------------------------

def norm_hex(mac: str) -> str:
    # Return MAC as 12 uppercase hex characters (no separators) or '' if invalid.
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(hexchars) < 6:
        return ""
    return hexchars.upper()


def mac_to_format(mac: str, fmt: str) -> str:
    # Convert a MAC into one of:
    #   - 'As seen'        -> original mac
    #   - 'AA:BB:CC:DD:EE:FF'
    #   - 'AAAA.BBBB.CCCC'
    if fmt == "As seen":
        return mac
    n = norm_hex(mac)
    if len(n) != 12:
        return mac

    if fmt == "AA:BB:CC:DD:EE:FF":
        return ":".join(n[i:i+2] for i in range(0, 12, 2))
    if fmt == "AAAA.BBBB.CCCC":
        return ".".join(n[i:i+4] for i in range(0, 12, 4))

    return mac


# ---------------------------------------------------------------------------
# Vendor DB: loading & lookup (Wireshark manuf format)
# ---------------------------------------------------------------------------

def _load_lines_from(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()


def fetch_manuf():
    # Download manuf file into CACHE_FILE (offline-friendly, never raises to caller).
    os.makedirs(CACHE_DIR, exist_ok=True)
    with urllib.request.urlopen(MANUF_URL, timeout=15) as response:
        content = response.read()
    with open(CACHE_FILE, "wb") as f:
        f.write(content)


def load_manuf():
    # Load Wireshark manuf database.
    #
    # Search order:
    #   1) Cached file in user profile (CACHE_FILE)
    #   2) Bundled 'manuf' (works both for normal script run and PyInstaller EXE)
    #   3) Fallback to empty DB
    #
    # Returns (buckets, masks):
    #   buckets: dict[int, dict[prefix_hex -> vendor]]
    #   masks:   sorted list of hex-lengths (largest first)

    lines = None

    # 1) Try cached file in user profile
    if os.path.isfile(CACHE_FILE):
        try:
            lines = _load_lines_from(CACHE_FILE)
        except Exception:
            lines = None

    # 2) Try bundled manuf (supports PyInstaller onefile via get_bundled_path)
    if lines is None:
        bundled = get_bundled_path("manuf")
        if os.path.isfile(bundled):
            try:
                lines = _load_lines_from(bundled)
                # Also copy to cache for next time
                os.makedirs(CACHE_DIR, exist_ok=True)
                with open(CACHE_FILE, "w", encoding="utf-8") as f:
                    f.writelines(lines)
            except Exception:
                lines = None

    # 3) Fallback: no manuf available → empty DB
    if lines is None:
        return {}, []

    buckets = {}  # key: hex_prefix_len, value: {prefix_hex -> vendor}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if not parts:
            continue

        prefix = parts[0]
        vendor = " ".join(parts[1:]) if len(parts) > 1 else ""

        # Extract mask bits (if present)
        if "/" in prefix:
            base, mask_str = prefix.split("/", 1)
            try:
                mask_bits = int(mask_str)
            except ValueError:
                mask_bits = 24
        else:
            base = prefix
            # Assume 24 bits for classic OUI if only 3 bytes; else scale
            hexchars = re.sub(r"[^0-9A-Fa-f]", "", base)
            mask_bits = len(hexchars) * 4

        base_hex = norm_hex(base)
        if not base_hex:
            continue

        # Number of hex chars to match according to mask_bits
        hex_len = mask_bits // 4
        base_hex = base_hex[:hex_len]

        if hex_len not in buckets:
            buckets[hex_len] = {}
        if base_hex not in buckets[hex_len]:
            buckets[hex_len][base_hex] = vendor

    masks = sorted(buckets.keys(), reverse=True)
    return buckets, masks


def lookup_vendor(mac: str, buckets, masks):
    # Lookup vendor name for given MAC using manuf buckets/masks.
    if not buckets or not masks:
        return ""
    n = norm_hex(mac)
    if len(n) < 6:
        return ""
    for hex_len in masks:
        if len(n) < hex_len:
            continue
        prefix = n[:hex_len]
        vendor = buckets[hex_len].get(prefix)
        if vendor:
            return vendor
    return ""


# ---------------------------------------------------------------------------
# Parsing Cisco outputs
# ---------------------------------------------------------------------------

MAC_RE = re.compile(
    r"([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{12}"
    r"|(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2})"
)

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
HOSTNAME_PROMPT_RE = re.compile(
    r"^\s*([A-Za-z0-9._\-]+)(?:\([^)]+\))*\s*[#>]"
)
HOSTNAME_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

SHOW_COMMAND_MARKERS = (
    "show mac address-table",
    "show mac-address-table",
    "show ip arp",
    "show arp",
)

HOSTNAME_STOP_WORDS = {
    "address",
    "age",
    "all",
    "dynamic",
    "flags",
    "internet",
    "interface",
    "legend",
    "mac",
    "ports",
    "protocol",
    "static",
    "total",
    "type",
    "vlan",
}


def parse_ios_mac_table(text: str):
    # Parse 'show mac address-table' output.
    # Returns list of (vlan, mac, type, iface).
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip header lines
        if line.lower().startswith("vlan") or "mac address" in line.lower():
            continue

        m = MAC_RE.search(line)
        if not m:
            continue

        mac = m.group(1)
        parts = line.split()

        vlan = ""
        typ = ""
        iface = ""

        # Heuristic: VLAN often first, interface last
        if len(parts) >= 3:
            vlan = parts[0]
            iface = parts[-1]
            # Somewhere in the middle there is TYPE (DYNAMIC/STATIC)
            for p in parts[1:-1]:
                if p.isalpha():
                    typ = p
                    break

        entries.append((vlan, mac, typ, iface))

    return entries


def parse_ios_arp_table(text: str):
    # Parse Cisco IOS/IOS-XE 'show ip arp', 'show ip arp vrf X', or 'show arp' output.
    # Returns list of (ip, mac, iface).
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Skip obvious header lines
        if line.lower().startswith("protocol") or line.lower().startswith("address"):
            continue
        if "Incomplete" in line:
            continue

        m_ip = IPV4_RE.search(line)
        m_mac = MAC_RE.search(line)
        if not m_ip or not m_mac:
            continue

        ip = m_ip.group(1)
        mac = m_mac.group(1)
        parts = line.split()
        iface = parts[-1] if parts else ""

        entries.append((ip, mac, iface))

    return entries


def _is_hostname_candidate(value: str) -> bool:
    value = (value or "").strip()
    if not HOSTNAME_TOKEN_RE.match(value):
        return False
    if value.isdigit():
        return False
    if value.lower() in HOSTNAME_STOP_WORDS:
        return False
    if MAC_RE.fullmatch(value) or IPV4_RE.fullmatch(value):
        return False
    return True


def _clean_hostname_candidate(line: str) -> str:
    candidate = (line or "").strip().strip("=:- ")
    if not candidate:
        return ""
    # Saved terminal logs often include a command after the prompt line.
    candidate = candidate.split()[0]
    return candidate if _is_hostname_candidate(candidate) else ""


def detect_hostname(text: str):
    # Try to detect hostname from CLI prompt lines or saved command-output logs.
    # Examples:
    #   Switch01# show mac address-table
    #   RTR01(config)# do show ip arp
    #   78-01-SW01
    #   ===== mac :: show mac address-table =====
    lines = [line.strip() for line in text.splitlines()]

    for line in lines:
        if not line:
            continue
        m = HOSTNAME_PROMPT_RE.match(line)
        if m and _is_hostname_candidate(m.group(1)):
            return m.group(1)

    first_candidate = ""
    previous_candidate = ""
    for line in lines:
        if not line:
            continue

        lower = line.lower()
        if any(marker in lower for marker in SHOW_COMMAND_MARKERS):
            if previous_candidate:
                return previous_candidate

        candidate = _clean_hostname_candidate(line)
        if candidate:
            if not first_candidate:
                first_candidate = candidate
            previous_candidate = candidate
            continue

        previous_candidate = ""

    # If the output starts with a standalone hostname, use it as a friendly
    # fallback. This catches SecureCRT/PuTTY logs that save the hostname as a
    # heading before the command output.
    return first_candidate


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def iface_sort_key(iface: str):
    # Simple sort key for interfaces (Gi1/0/1, Te1/1/1, Po1, etc.).
    if not iface:
        return (999, 999, 999, iface)

    # Detect port-channel specially
    if iface.startswith("Po"):
        try:
            idx = int(re.sub(r"\D", "", iface) or "0")
        except ValueError:
            idx = 999
        return (3, idx, 0, iface)

    # Try to split like Gi1/0/1 -> (Gi, 1, 0, 1)
    m = re.match(r"([A-Za-z]+)(\d+)(?:/(\d+))?(?:/(\d+))?", iface)
    if not m:
        return (2, 999, 999, iface)

    nums = [int(x) if x is not None else 0 for x in m.groups()[1:]]
    return (1, *nums, iface)


def correlate_mac_and_arp(
    switch_inputs,
    router_inputs,
    buckets,
    masks,
    mac_fmt="AA:BB:CC:DD:EE:FF",
    exclude_po=True,
    exclude_cpu=False,
):
    # switch_inputs: list of dicts: { "name": str, "text": str }
    # router_inputs: list of dicts: { "name": str, "text": str }
    # Returns list of rows:
    #   (switch_name, vlan, sw_iface, mac_fmt_out, vendor, ip, router_name, arp_iface)

    # 1. Build ARP index across all routers
    arp_index = {}  # key: normalized MAC (12 hex), value: list of dicts

    for r in router_inputs:
        raw = (r.get("text") or "").strip()
        if not raw:
            continue
        router_name = (r.get("name") or "").strip()
        if not router_name:
            auto = detect_hostname(raw)
            if auto:
                router_name = auto

        arp_rows = parse_ios_arp_table(raw)
        for ip, mac, iface in arp_rows:
            key = norm_hex(mac)
            if len(key) != 12:
                continue
            arp_index.setdefault(key, []).append({
                "ip": ip,
                "router": router_name,
                "iface": iface,
            })

    # 2. Walk all switch MAC tables and correlate
    results = []

    for s in switch_inputs:
        raw = (s.get("text") or "").strip()
        if not raw:
            continue
        sw_name = (s.get("name") or "").strip()
        if not sw_name:
            auto = detect_hostname(raw)
            if auto:
                sw_name = auto

        mac_rows = parse_ios_mac_table(raw)
        for vlan, mac, typ, iface in mac_rows:
            # Filters
            if exclude_po and iface.startswith("Po"):
                continue
            if exclude_cpu and iface.upper() == "CPU":
                continue

            norm = norm_hex(mac)
            vendor = lookup_vendor(mac, buckets, masks)
            mac_out = mac_to_format(mac, mac_fmt) if mac_fmt != "As seen" else mac

            matches = arp_index.get(norm)

            if not matches:
                # No ARP match at all → still keep the MAC
                results.append((
                    sw_name, vlan, iface, mac_out, vendor,
                    "", "", ""   # ip, router_name, arp_iface
                ))
            else:
                # Possibly multiple IPs and/or routers for the same MAC
                for m in matches:
                    results.append((
                        sw_name, vlan, iface, mac_out, vendor,
                        m["ip"], m["router"], m["iface"]
                    ))

    return results


THEMES = {
    "light": {
        "bg": "#f0f0f0",
        "panel_bg": "#f0f0f0",
        "fg": "#000000",
        "muted_fg": "#333333",
        "entry_bg": "#ffffff",
        "button_bg": "#f5f5f5",
        "button_active": "#e5e5e5",
        "button_pressed": "#d9d9d9",
        "border": "#b8b8b8",
        "tree_bg": "#ffffff",
        "tree_alt": "#f7f7f7",
        "heading_bg": "#eeeeee",
        "select_bg": "#0078d7",
        "select_fg": "#ffffff",
        "disabled_fg": "#6f6f6f",
        "insert": "#000000",
    },
    "dark": {
        "bg": "#1f2227",
        "panel_bg": "#252a31",
        "fg": "#f1f5f9",
        "muted_fg": "#cbd5e1",
        "entry_bg": "#111827",
        "button_bg": "#303741",
        "button_active": "#3b4450",
        "button_pressed": "#46515f",
        "border": "#46515f",
        "tree_bg": "#151a20",
        "tree_alt": "#1d232b",
        "heading_bg": "#2b323b",
        "select_bg": "#0f766e",
        "select_fg": "#ffffff",
        "disabled_fg": "#8b95a3",
        "insert": "#f8fafc",
    },
}


# ---------------------------------------------------------------------------
# GUI application
# ---------------------------------------------------------------------------

class App:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME)
        icon_path = get_bundled_path("icon.ico")
        if os.path.isfile(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except tk.TclError:
                pass
        self.style = ttk.Style(root)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")

        # Load vendor DB (offline-tolerant, supports bundled manuf)
        try:
            self.buckets, self.masks = load_manuf()
        except Exception:
            self.buckets, self.masks = {}, []

        self.last_rows = []
        self.text_widgets = []
        self.dark_mode = tk.BooleanVar(value=True)

        main = ttk.Frame(root)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        # Top options row
        opt_row = ttk.Frame(main)
        opt_row.pack(fill="x", pady=(0, 6))

        ttk.Label(opt_row, text="MAC Format:").pack(side="left")
        self.mac_fmt = tk.StringVar(value="AA:BB:CC:DD:EE:FF")
        fmt_box = ttk.Combobox(
            opt_row,
            textvariable=self.mac_fmt,
            values=["As seen", "AA:BB:CC:DD:EE:FF", "AAAA.BBBB.CCCC"],
            state="readonly",
            width=20,
        )
        fmt_box.pack(side="left", padx=(4, 12))

        self.exclude_po = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opt_row,
            text="Exclude Port-Channels (Po*)",
            variable=self.exclude_po
        ).pack(side="left")

        self.exclude_cpu = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opt_row,
            text="Exclude CPU MACs",
            variable=self.exclude_cpu
        ).pack(side="left", padx=(8, 0))

        self.only_ip = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opt_row,
            text="Only rows with IP match",
            variable=self.only_ip
        ).pack(side="left", padx=(8, 0))

        ttk.Label(opt_row, text=" ").pack(side="left", padx=4)  # spacer

        ttk.Button(opt_row, text="Lookup", command=self.lookup).pack(side="left", padx=(4, 2))
        ttk.Button(opt_row, text="Export CSV", command=self.export_csv).pack(side="left", padx=2)
        ttk.Button(opt_row, text="Clear All", command=self.clear_all).pack(side="left", padx=(12, 0))

        # Notebook with device tabs and occasional settings.
        nb = ttk.Notebook(main)
        nb.pack(fill="both", expand=True, pady=(4, 6))

        self.switch_blocks = []
        self.router_blocks = []

        for i in range(1, 6):
            frame = ttk.Frame(nb)
            nb.add(frame, text=f"SW{i}")
            block = self._build_device_tab(frame, is_router=False, index=i)
            self.switch_blocks.append(block)

        for i in range(1, 3):
            frame = ttk.Frame(nb)
            nb.add(frame, text=f"RT{i}-ARP")
            block = self._build_device_tab(frame, is_router=True, index=i)
            self.router_blocks.append(block)

        settings_frame = ttk.Frame(nb)
        nb.add(settings_frame, text="Settings")
        self._build_settings_tab(settings_frame)

        # Result table
        tree_frame = ttk.Frame(main)
        tree_frame.pack(fill="both", expand=True)

        columns = ("switch", "vlan", "iface", "mac", "vendor", "ip", "router", "arp_iface")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.heading("switch", text="Switch")
        self.tree.heading("vlan", text="VLAN")
        self.tree.heading("iface", text="Interface")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("vendor", text="Vendor")
        self.tree.heading("ip", text="IP")
        self.tree.heading("router", text="Router")
        self.tree.heading("arp_iface", text="ARP Interface")

        self.tree.column("switch", width=140, anchor="w")
        self.tree.column("vlan", width=60, anchor="center")
        self.tree.column("iface", width=120, anchor="w")
        self.tree.column("mac", width=160, anchor="w")
        self.tree.column("vendor", width=260, anchor="w")
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("router", width=140, anchor="w")
        self.tree.column("arp_iface", width=120, anchor="w")

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(main, textvariable=self.status_var, anchor="w")
        status.pack(fill="x", pady=(4, 0))
        self._apply_theme()

    # ------------------------------------------------------------------
    # Theme handling
    # ------------------------------------------------------------------

    def _style_configure(self, style_name, **options):
        try:
            self.style.configure(style_name, **options)
        except tk.TclError:
            pass

    def _style_map(self, style_name, **options):
        try:
            self.style.map(style_name, **options)
        except tk.TclError:
            pass

    def _apply_theme(self):
        palette = THEMES["dark"] if self.dark_mode.get() else THEMES["light"]

        self.root.configure(bg=palette["bg"])
        self.root.option_add("*TCombobox*Listbox.background", palette["entry_bg"])
        self.root.option_add("*TCombobox*Listbox.foreground", palette["fg"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", palette["select_bg"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", palette["select_fg"])

        self._style_configure(
            ".",
            background=palette["bg"],
            foreground=palette["fg"],
            fieldbackground=palette["entry_bg"],
            bordercolor=palette["border"],
            lightcolor=palette["border"],
            darkcolor=palette["border"],
            troughcolor=palette["panel_bg"],
        )
        self._style_configure("TFrame", background=palette["bg"])
        self._style_configure("TLabel", background=palette["bg"], foreground=palette["fg"])
        self._style_configure(
            "TLabelframe",
            background=palette["bg"],
            foreground=palette["fg"],
            bordercolor=palette["border"],
            relief="solid",
        )
        self._style_configure(
            "TLabelframe.Label",
            background=palette["bg"],
            foreground=palette["fg"],
        )
        self._style_configure(
            "TCheckbutton",
            background=palette["bg"],
            foreground=palette["fg"],
        )
        self._style_map(
            "TCheckbutton",
            background=[("active", palette["bg"])],
            foreground=[("disabled", palette["disabled_fg"]), ("active", palette["fg"])],
        )
        self._style_configure(
            "TButton",
            background=palette["button_bg"],
            foreground=palette["fg"],
            bordercolor=palette["border"],
            focusthickness=1,
            focuscolor=palette["select_bg"],
            padding=(8, 3),
        )
        self._style_map(
            "TButton",
            background=[
                ("pressed", palette["button_pressed"]),
                ("active", palette["button_active"]),
            ],
            foreground=[("disabled", palette["disabled_fg"])],
        )
        self._style_configure(
            "TEntry",
            fieldbackground=palette["entry_bg"],
            foreground=palette["fg"],
            insertcolor=palette["insert"],
            bordercolor=palette["border"],
        )
        self._style_configure(
            "TCombobox",
            fieldbackground=palette["entry_bg"],
            background=palette["button_bg"],
            foreground=palette["fg"],
            arrowcolor=palette["fg"],
            bordercolor=palette["border"],
        )
        self._style_map(
            "TCombobox",
            fieldbackground=[("readonly", palette["entry_bg"])],
            selectbackground=[("readonly", palette["entry_bg"])],
            selectforeground=[("readonly", palette["fg"])],
        )
        self._style_configure(
            "TNotebook",
            background=palette["bg"],
            bordercolor=palette["border"],
        )
        self._style_configure(
            "TNotebook.Tab",
            background=palette["button_bg"],
            foreground=palette["fg"],
            padding=(8, 4),
        )
        self._style_map(
            "TNotebook.Tab",
            background=[
                ("selected", palette["panel_bg"]),
                ("active", palette["button_active"]),
            ],
            foreground=[("disabled", palette["disabled_fg"]), ("selected", palette["fg"])],
        )
        self._style_configure(
            "Treeview",
            background=palette["tree_bg"],
            fieldbackground=palette["tree_bg"],
            foreground=palette["fg"],
            bordercolor=palette["border"],
            rowheight=23,
        )
        self._style_map(
            "Treeview",
            background=[("selected", palette["select_bg"])],
            foreground=[("selected", palette["select_fg"])],
        )
        self._style_configure(
            "Treeview.Heading",
            background=palette["heading_bg"],
            foreground=palette["fg"],
            bordercolor=palette["border"],
            relief="flat",
        )
        self._style_map(
            "Treeview.Heading",
            background=[("active", palette["button_active"])],
        )
        self._style_configure(
            "Vertical.TScrollbar",
            background=palette["button_bg"],
            troughcolor=palette["panel_bg"],
            arrowcolor=palette["fg"],
            bordercolor=palette["border"],
        )
        self._style_configure(
            "Horizontal.TScrollbar",
            background=palette["button_bg"],
            troughcolor=palette["panel_bg"],
            arrowcolor=palette["fg"],
            bordercolor=palette["border"],
        )

        for txt in self.text_widgets:
            txt.configure(
                background=palette["entry_bg"],
                foreground=palette["fg"],
                insertbackground=palette["insert"],
                selectbackground=palette["select_bg"],
                selectforeground=palette["select_fg"],
                highlightbackground=palette["border"],
                highlightcolor=palette["select_bg"],
                relief="solid",
                borderwidth=1,
            )

        if hasattr(self, "tree"):
            self.tree.tag_configure("evenrow", background=palette["tree_bg"], foreground=palette["fg"])
            self.tree.tag_configure("oddrow", background=palette["tree_alt"], foreground=palette["fg"])

    # ------------------------------------------------------------------
    # Tab builder
    # ------------------------------------------------------------------

    def _build_device_tab(self, frame, is_router: bool, index: int):
        # Build one device tab: either switch or router.
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=(4, 4))

        ttk.Label(top, text="Hostname:").pack(side="left")
        default_host = f"RT{index}" if is_router else f"SW{index}"
        host_var = tk.StringVar(value=default_host)
        ttk.Entry(top, textvariable=host_var, width=24).pack(side="left", padx=(4, 8))

        paste_btn = ttk.Button(
            top,
            text="Paste",
            command=lambda f=frame: self._paste_into_tab(f)
        )
        paste_btn.pack(side="left", padx=2)

        load_btn = ttk.Button(
            top,
            text="Load File",
            command=lambda f=frame: self._load_file_into_tab(f)
        )
        load_btn.pack(side="left", padx=2)

        hint_text = "Paste 'show mac address-table' output"
        if is_router:
            hint_text = "Paste 'show ip arp' (or 'show ip arp vrf ...') output"

        ttk.Label(top, text=hint_text).pack(side="left", padx=(10, 0))

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill="both", expand=True)

        txt = tk.Text(text_frame, wrap="none", height=12)
        self.text_widgets.append(txt)
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=txt.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        txt.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

        return {
            "frame": frame,
            "host_var": host_var,
            "default_host": default_host,
            "txt": txt,
        }

    def _build_settings_tab(self, frame):
        content = ttk.Frame(frame)
        content.pack(anchor="nw", fill="x", padx=8, pady=8)

        appearance = ttk.LabelFrame(content, text="Appearance")
        appearance.pack(anchor="nw", fill="x", pady=(0, 8))
        ttk.Checkbutton(
            appearance,
            text="Dark Mode",
            variable=self.dark_mode,
            command=self._apply_theme
        ).pack(anchor="w", padx=8, pady=8)

        vendor_db = ttk.LabelFrame(content, text="Vendor Database")
        vendor_db.pack(anchor="nw", fill="x", pady=(0, 8))
        db_row = ttk.Frame(vendor_db)
        db_row.pack(anchor="w", padx=8, pady=8)
        ttk.Button(db_row, text="Update DB", command=self.update_db).pack(side="left", padx=(0, 6))
        ttk.Button(db_row, text="Load DB File", command=self.load_db_file).pack(side="left")

        credits = ttk.LabelFrame(content, text="Credits")
        credits.pack(anchor="nw", fill="x")
        ttk.Label(credits, text=f"Developer: {DEVELOPER_NAME}").pack(anchor="w", padx=8, pady=(8, 2))
        ttk.Label(credits, text=f"Tag: {DEVELOPER_TAG}").pack(anchor="w", padx=8, pady=2)
        ttk.Label(credits, text=f"Version: {APP_VERSION}").pack(anchor="w", padx=8, pady=(2, 8))

    # ------------------------------------------------------------------
    # Helpers for tabs
    # ------------------------------------------------------------------

    def _find_block_by_frame(self, frame):
        for b in self.switch_blocks + self.router_blocks:
            if b["frame"] is frame:
                return b
        return None

    def _can_replace_hostname(self, block):
        current = block["host_var"].get().strip()
        default_host = block.get("default_host", "")
        return not current or current == default_host

    def _prefill_hostname(self, block, text: str, fallback: str = ""):
        if not self._can_replace_hostname(block):
            return

        auto = detect_hostname(text)
        if not auto and fallback:
            auto = _clean_hostname_candidate(fallback)
        if auto:
            block["host_var"].set(auto)

    def _paste_into_tab(self, frame):
        block = self._find_block_by_frame(frame)
        if not block:
            return
        try:
            clip = self.root.clipboard_get()
        except Exception:
            clip = ""
        if not clip:
            return
        txt = block["txt"]
        txt.delete("1.0", "end")
        txt.insert("1.0", clip)
        self._prefill_hostname(block, clip)

    def _load_file_into_tab(self, frame):
        block = self._find_block_by_frame(frame)
        if not block:
            return
        p = filedialog.askopenfilename(
            title="Select text file",
            filetypes=[("Text files", "*.txt *.log *.out *.cfg"), ("All files", "*.*")]
        )
        if not p:
            return
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file:\n{e}")
            return

        txt = block["txt"]
        txt.delete("1.0", "end")
        txt.insert("1.0", content)
        self._prefill_hostname(block, content, fallback=Path(p).stem)

    # ------------------------------------------------------------------
    # Status handling
    # ------------------------------------------------------------------

    def set_status(self, msg: str):
        self.status_var.set(msg)
        self.root.update_idletasks()

    def set_status_async(self, msg: str):
        self.root.after(0, self.set_status, msg)

    # ------------------------------------------------------------------
    # Core actions
    # ------------------------------------------------------------------

    def _clear_results(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.last_rows = []

    def _collect_lookup_inputs(self):
        switch_inputs = []
        for b in self.switch_blocks:
            txt = b["txt"].get("1.0", "end")
            name = b["host_var"].get().strip()
            switch_inputs.append({"name": name, "text": txt})

        router_inputs = []
        for b in self.router_blocks:
            txt = b["txt"].get("1.0", "end")
            name = b["host_var"].get().strip()
            router_inputs.append({"name": name, "text": txt})

        return {
            "switch_inputs": switch_inputs,
            "router_inputs": router_inputs,
            "mac_fmt": self.mac_fmt.get(),
            "exclude_po": self.exclude_po.get(),
            "exclude_cpu": self.exclude_cpu.get(),
            "only_ip": self.only_ip.get(),
        }

    def lookup(self):
        self._run_lookup()

    def _run_lookup(self, on_complete=None):
        # Correlate MAC tables with ARP tables across all devices.
        self._clear_results()
        inputs = self._collect_lookup_inputs()

        self.set_status("Resolving MACs and correlating with ARP...")

        def run():
            try:
                rows = correlate_mac_and_arp(
                    inputs["switch_inputs"],
                    inputs["router_inputs"],
                    self.buckets,
                    self.masks,
                    mac_fmt=inputs["mac_fmt"],
                    exclude_po=inputs["exclude_po"],
                    exclude_cpu=inputs["exclude_cpu"],
                )

                # Optional filter: only rows with IP match
                if inputs["only_ip"]:
                    rows = [r for r in rows if str(r[5]).strip()]

                # Sort results for display (Switch, VLAN, Interface)
                def sort_key(r):
                    sw, vlan, iface = r[0], r[1], r[2]
                    try:
                        vlan_num = int(vlan)
                    except Exception:
                        vlan_num = 9999
                    return (sw or "", vlan_num, iface_sort_key(iface or ""))

                rows.sort(key=sort_key)

                self.root.after(0, self._finish_lookup, rows, on_complete)
            except Exception as e:
                self.root.after(0, lambda: self.set_status(f"Error: {e}"))

        threading.Thread(target=run, daemon=True).start()

    def _finish_lookup(self, rows, on_complete=None):
        self._populate_tree(rows)
        if on_complete:
            on_complete()

    def _populate_tree(self, rows):
        self.last_rows = rows
        for index, r in enumerate(rows):
            tag = "evenrow" if index % 2 == 0 else "oddrow"
            self.tree.insert("", "end", values=r, tags=(tag,))
        self.set_status(f"{len(rows)} row(s) displayed")

    def export_csv(self):
        self._run_lookup(on_complete=self._export_current_rows)

    def _export_current_rows(self):
        # Export current table to a CSV file, sorted by Hostname then Interface.
        if not self.last_rows:
            messagebox.showinfo("Export CSV", "No data to export.")
            return

        # Sort by Switch (hostname), then Interface numerically
        rows = sorted(
            self.last_rows,
            key=lambda r: ((r[0] or ""), iface_sort_key(r[2] or ""))
        )

        p = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not p:
            return
        try:
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Switch", "VLAN", "Interface", "MAC", "Vendor",
                            "IP", "Router", "ARP_Interface"])
                for r in rows:
                    w.writerow(r)
            self.set_status(f"Exported {len(rows)} row(s) to {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV:\n{e}")

    def clear_all(self):
        # Clear all text inputs and table.
        for b in self.switch_blocks + self.router_blocks:
            b["txt"].delete("1.0", "end")
            b["host_var"].set(b.get("default_host", ""))
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.last_rows = []
        self.set_status("Cleared")

    # ------------------------------------------------------------------
    # Vendor DB actions
    # ------------------------------------------------------------------

    def update_db(self):
        # Download latest Wireshark manuf file and reload DB.
        def run():
            try:
                self.set_status_async("Updating vendor DB from Wireshark...")
                fetch_manuf()
                self.buckets, self.masks = load_manuf()
                self.set_status_async("Vendor DB updated")
            except Exception as e:
                self.set_status_async("Vendor DB update failed")
                self.root.after(
                    0,
                    lambda err=e: messagebox.showerror(
                        "Error",
                        f"Vendor DB update failed:\n{err}"
                    )
                )

        threading.Thread(target=run, daemon=True).start()

    def load_db_file(self):
        # Load a local manuf file into the cache and reload DB.
        p = filedialog.askopenfilename(
            title="Select manuf file",
            filetypes=[("manuf or text", "*.*")]
        )
        if not p:
            return
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            with open(p, "rb") as src, open(CACHE_FILE, "wb") as dst:
                dst.write(src.read())
            self.buckets, self.masks = load_manuf()
            self.set_status(f"Loaded vendor DB from {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load manuf file:\n{e}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    app = App(root)
    root.geometry("1200x800")
    root.mainloop()


if __name__ == "__main__":
    main()
