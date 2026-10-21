import os
import sys
import re
import csv
import threading
import urllib.request
import zipfile
import time
import traceback
import faulthandler
import platform
from pathlib import Path
from xml.sax.saxutils import escape
from tools_ui import NetworkToolsView, Tooltip, WORKSPACE_TOP_GAP
from resolver_workflow import (build_input_report, filter_sort_rows, is_current_lookup_result,
                               read_session, write_session)
from app_preferences import (
    COLOR_LABELS, MAC_FORMATS, THEMES, default_preferences, effective_palette,
    load_preferences, normalize_color, save_preferences, contrast_ratio,
)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
CACHE_DIR = os.path.join(Path.home(), ".oui_lookup")
CACHE_FILE = os.path.join(CACHE_DIR, "manuf")
APP_NAME = "SwitchPort Resolver"
APP_VERSION = "4.1.0"
DEVELOPER_TAG = "746f617374"
RESULT_HEADERS = ("Switch", "VLAN", "Interface", "MAC", "Vendor", "IP", "Router", "ARP Interface")
CSV_HEADERS = ("Switch", "VLAN", "Interface", "MAC", "Vendor", "IP", "Router", "ARP_Interface")
CRASH_LOG_NAME = "switchport-resolver.log"

# ---------------------------------------------------------------------------
# Crash/debug logging
# ---------------------------------------------------------------------------

_LOG_FILE_HANDLE = None


def desktop_path():
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            desktop_guid = GUID(
                0xB4BFCC3A,
                0xDB2C,
                0x424C,
                (ctypes.c_ubyte * 8)(0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41),
            )
            path_ptr = ctypes.c_wchar_p()
            result = ctypes.windll.shell32.SHGetKnownFolderPath(
                ctypes.byref(desktop_guid),
                0,
                None,
                ctypes.byref(path_ptr),
            )
            if result == 0 and path_ptr.value and os.path.isdir(path_ptr.value):
                path = path_ptr.value
                ctypes.windll.ole32.CoTaskMemFree(path_ptr)
                return path
        except Exception:
            pass

        env_desktop = os.path.join(os.environ.get("USERPROFILE", str(Path.home())), "Desktop")
        if os.path.isdir(env_desktop):
            return env_desktop

        onedrive = os.environ.get("OneDrive") or os.environ.get("OneDriveCommercial")
        if onedrive:
            onedrive_desktop = os.path.join(onedrive, "Desktop")
            if os.path.isdir(onedrive_desktop):
                return onedrive_desktop

    desktop = os.path.join(Path.home(), "Desktop")
    return desktop if os.path.isdir(desktop) else str(Path.home())


def crash_log_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(Path.home(), ".local", "share")
    return os.path.join(base, "SwitchPort Resolver", "Logs", CRASH_LOG_NAME)


def set_windows_titlebar_theme(root, dark):
    """Use the OS-supported dark caption when available; silently fall back."""
    if os.name != "nt":
        return
    try:
        import ctypes
        root.update_idletasks()
        get_parent = ctypes.windll.user32.GetParent
        get_parent.argtypes = [ctypes.c_void_p]
        get_parent.restype = ctypes.c_void_p
        hwnd = get_parent(root.winfo_id()) or root.winfo_id()
        value = ctypes.c_int(int(bool(dark)))
        set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
        set_attribute.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
        set_attribute.restype = ctypes.c_int
        for attribute in (20, 19):
            if set_attribute(
                    hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except Exception:
        pass


def _prepare_log():
    path = crash_log_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.isfile(path) and os.path.getsize(path) > 2_000_000:
        os.replace(path, path + ".previous")
    return path


def log_debug(message):
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        path = crash_log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def log_exception(prefix, exc_type=None, exc_value=None, exc_tb=None):
    if exc_type is None:
        exc_type, exc_value, exc_tb = sys.exc_info()
    # Exception messages may contain input snippets or user file paths.
    details = f"{getattr(exc_type, '__name__', 'UnknownError')}\n" + "".join(traceback.format_tb(exc_tb))
    log_debug(f"{prefix}\n{details}")


def setup_crash_logging():
    global _LOG_FILE_HANDLE

    try:
        _prepare_log()
    except OSError:
        pass

    log_debug("")
    log_debug("=" * 80)
    log_debug(f"{APP_NAME} {APP_VERSION} starting")
    log_debug(f"Frozen: {bool(getattr(sys, 'frozen', False))}")
    log_debug(f"Python: {sys.version}")
    log_debug(f"Platform: {sys.platform}")

    try:
        _LOG_FILE_HANDLE = open(crash_log_path(), "a", encoding="utf-8", errors="ignore")
        faulthandler.enable(file=_LOG_FILE_HANDLE, all_threads=True)
        log_debug("faulthandler enabled")
    except Exception:
        _LOG_FILE_HANDLE = None
        log_exception("Failed to enable faulthandler")

    def excepthook(exc_type, exc_value, exc_tb):
        log_exception("Unhandled main-thread exception", exc_type, exc_value, exc_tb)
        if sys.__excepthook__:
            sys.__excepthook__(exc_type, exc_value, exc_tb)

    sys.excepthook = excepthook

    if hasattr(threading, "excepthook"):
        def thread_excepthook(args):
            log_exception(
                f"Unhandled thread exception in {getattr(args.thread, 'name', 'unknown')}",
                args.exc_type,
                args.exc_value,
                args.exc_traceback,
            )

        threading.excepthook = thread_excepthook

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


def _excel_col_name(index: int) -> str:
    name = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def _xml_clean(value) -> str:
    text = "" if value is None else str(value)
    cleaned = []
    for ch in text:
        code = ord(ch)
        if code in (9, 10, 13) or 32 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD:
            cleaned.append(ch)
    return "".join(cleaned)


def _xml_text(value) -> str:
    return escape(_xml_clean(value))


def _xml_attr(value) -> str:
    return escape(_xml_clean(value), {'"': "&quot;"})


def _xlsx_cell(row_num: int, col_num: int, value, header: str = "", style=None) -> str:
    cell_ref = f"{_excel_col_name(col_num)}{row_num}"
    style_attr = f' s="{style}"' if style is not None else ""
    text = _xml_clean(value).strip()

    if header == "VLAN" and re.fullmatch(r"\d+", text or ""):
        return f'<c r="{cell_ref}"{style_attr}><v>{int(text)}</v></c>'

    return (
        f'<c r="{cell_ref}" t="inlineStr"{style_attr}>'
        f'<is><t xml:space="preserve">{_xml_text(value)}</t></is></c>'
    )


def _xlsx_row(row_num: int, values, headers=RESULT_HEADERS, style=None) -> str:
    cells = []
    for col_num, header in enumerate(headers, 1):
        value = values[col_num - 1] if col_num <= len(values) else ""
        cells.append(_xlsx_cell(row_num, col_num, value, header=header, style=style))
    return f'<row r="{row_num}">{"".join(cells)}</row>'


def write_xlsx_with_filters(path: str, rows, headers=RESULT_HEADERS):
    # Write a small XLSX workbook using only the standard library. The exported
    # range is an Excel table, so users get filter/sort dropdowns on every column.
    max_rows = 1048576
    if len(rows) + 1 > max_rows:
        raise ValueError(f"Excel supports up to {max_rows - 1} exported data rows.")

    headers = tuple(headers)
    last_col = _excel_col_name(len(headers))
    last_row = len(rows) + 1
    table_ref = f"A1:{last_col}{last_row}"

    col_widths = (22, 10, 18, 22, 36, 18, 22, 20)
    cols_xml = "".join(
        f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>'
        for i, width in enumerate(col_widths[:len(headers)], 1)
    )

    sheet_rows = [_xlsx_row(1, headers, headers=headers, style=1)]
    for row_num, row in enumerate(rows, 2):
        sheet_rows.append(_xlsx_row(row_num, row, headers=headers))
    sheet_data = "".join(sheet_rows)

    sheet_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <dimension ref="{table_ref}"/>
  <sheetViews>
    <sheetView workbookViewId="0">
      <pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>
      <selection pane="bottomLeft"/>
    </sheetView>
  </sheetViews>
  <sheetFormatPr defaultRowHeight="15"/>
  <cols>{cols_xml}</cols>
  <sheetData>{sheet_data}</sheetData>
  <tableParts count="1"><tablePart r:id="rId1"/></tableParts>
</worksheet>'''

    table_columns = "".join(
        f'<tableColumn id="{i}" name="{_xml_attr(header)}"/>'
        for i, header in enumerate(headers, 1)
    )
    table_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<table xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" id="1" name="SwitchPortResults" displayName="SwitchPortResults" ref="{table_ref}" totalsRowShown="0">
  <autoFilter ref="{table_ref}"/>
  <tableColumns count="{len(headers)}">{table_columns}</tableColumns>
  <tableStyleInfo name="TableStyleMedium2" showFirstColumn="0" showLastColumn="0" showRowStripes="1" showColumnStripes="0"/>
</table>'''

    styles_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font>
    <font><b/><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font>
  </fonts>
  <fills count="2">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
  </fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="2">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''

    workbook_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Results" sheetId="1" r:id="rId1"/></sheets>
</workbook>'''

    content_types_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/tables/table1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>'''

    root_rels_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''

    workbook_rels_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>'''

    sheet_rels_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/table" Target="../tables/table1.xml"/>
</Relationships>'''

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        zf.writestr("xl/worksheets/_rels/sheet1.xml.rels", sheet_rels_xml)
        zf.writestr("xl/tables/table1.xml", table_xml)
        zf.writestr("xl/styles.xml", styles_xml)


def prepare_xlsx_export(rows):
    # Keep MAC-only exports focused on the columns that contain useful data.
    # This also ensures Excel's table/filter range does not extend across three
    # completely empty ARP columns when no router input was supplied.
    has_arp_data = any(
        any(str(row[index] or "").strip() for index in (5, 6, 7))
        for row in rows
    )
    if has_arp_data:
        return tuple(RESULT_HEADERS), list(rows)

    headers = tuple(RESULT_HEADERS[:5])
    export_rows = [tuple(row[:5]) for row in rows]
    return headers, export_rows


# ---------------------------------------------------------------------------
# Native Windows file drag/drop support
# ---------------------------------------------------------------------------

class WindowsFileDropManager:
    WM_DROPFILES = 0x0233
    GWLP_WNDPROC = -4

    def __init__(self, root, callback):
        self.root = root
        self.callback = callback
        self.enabled = False
        self._registered = False
        self._old_proc = None
        self._proc = None
        self._pending_drops = []
        log_debug("Initializing Windows drag/drop manager")

        if os.name != "nt":
            log_debug("Drag/drop disabled: non-Windows OS")
            return

        try:
            import ctypes
            from ctypes import wintypes

            self.ctypes = ctypes
            self.wintypes = wintypes
            self.user32 = ctypes.windll.user32
            self.shell32 = ctypes.windll.shell32

            self.LRESULT = ctypes.c_ssize_t
            self.WPARAM = ctypes.c_size_t
            self.LPARAM = ctypes.c_ssize_t
            self.WNDPROC = ctypes.WINFUNCTYPE(
                self.LRESULT,
                wintypes.HWND,
                wintypes.UINT,
                self.WPARAM,
                self.LPARAM,
            )

            self._set_window_long = getattr(
                self.user32,
                "SetWindowLongPtrW",
                self.user32.SetWindowLongW,
            )
            self._set_window_long.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            self._set_window_long.restype = ctypes.c_void_p

            self.user32.CallWindowProcW.argtypes = [
                ctypes.c_void_p,
                wintypes.HWND,
                wintypes.UINT,
                self.WPARAM,
                self.LPARAM,
            ]
            self.user32.CallWindowProcW.restype = self.LRESULT
            self.user32.DefWindowProcW.argtypes = [
                wintypes.HWND,
                wintypes.UINT,
                self.WPARAM,
                self.LPARAM,
            ]
            self.user32.DefWindowProcW.restype = self.LRESULT

            self.shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
            self.shell32.DragAcceptFiles.restype = None
            self.shell32.DragQueryFileW.argtypes = [
                wintypes.HANDLE,
                wintypes.UINT,
                wintypes.LPWSTR,
                wintypes.UINT,
            ]
            self.shell32.DragQueryFileW.restype = wintypes.UINT
            self.shell32.DragQueryPoint.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.POINT),
            ]
            self.shell32.DragQueryPoint.restype = wintypes.BOOL
            self.shell32.DragFinish.argtypes = [wintypes.HANDLE]
            self.shell32.DragFinish.restype = None

            self.enabled = True
            log_debug("Windows drag/drop manager initialized")
        except Exception:
            self.enabled = False
            log_exception("Windows drag/drop manager initialization failed")

    def register(self, widget):
        if not self.enabled:
            log_debug("Drag/drop registration skipped: manager disabled")
            return False
        if self._registered:
            return True

        try:
            widget.update_idletasks()
            hwnd = self.wintypes.HWND(widget.winfo_id())
            log_debug(f"Registering drag/drop root window hwnd={int(widget.winfo_id())}")

            def wndproc(hwnd_arg, msg, wparam, lparam):
                try:
                    if msg == self.WM_DROPFILES:
                        log_debug("WM_DROPFILES received")
                        files, point = self._query_drop_files(wparam)
                        log_debug(f"WM_DROPFILES query complete: files={len(files)} point={point}")
                        self.shell32.DragFinish(wparam)
                        log_debug("DragFinish complete")
                        if files:
                            self._pending_drops.append((files, point))
                            log_debug("Drop queued for Tk mainloop polling")
                        return 0

                    return self._call_original(hwnd_arg, msg, wparam, lparam)
                except Exception:
                    log_exception("Exception inside native drag/drop window procedure")
                    return self._call_original(hwnd_arg, msg, wparam, lparam)

            proc = self.WNDPROC(wndproc)
            old_proc = self._set_window_long(
                hwnd,
                self.GWLP_WNDPROC,
                self.ctypes.cast(proc, self.ctypes.c_void_p),
            )
            if not old_proc:
                return False

            self._old_proc = old_proc
            self._proc = proc
            self._registered = True
            self.shell32.DragAcceptFiles(hwnd, True)
            log_debug(f"Drag/drop registration succeeded old_proc={old_proc}")
            return True
        except Exception:
            log_exception("Drag/drop registration failed")
            return False

    def _call_original(self, hwnd, msg, wparam, lparam):
        if self._old_proc:
            return self.user32.CallWindowProcW(self._old_proc, hwnd, msg, wparam, lparam)
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _query_drop_files(self, hdrop):
        log_debug("Querying dropped files")
        point = None
        try:
            pt = self.wintypes.POINT()
            if self.shell32.DragQueryPoint(hdrop, self.ctypes.byref(pt)):
                point = (pt.x, pt.y)
        except Exception:
            log_exception("Could not query drop point")
            point = None

        count = self.shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
        files = []
        for index in range(count):
            length = self.shell32.DragQueryFileW(hdrop, index, None, 0)
            buf = self.ctypes.create_unicode_buffer(length + 1)
            self.shell32.DragQueryFileW(hdrop, index, buf, length + 1)
            files.append(buf.value)
            log_debug(f"Dropped file[{index}] received")
        return files, point

    def pop_pending_drops(self):
        drops = self._pending_drops[:]
        self._pending_drops = []
        return drops

    def widget_for_drop_point(self, point):
        widget = self.root
        if point:
            try:
                x = self.root.winfo_rootx() + point[0]
                y = self.root.winfo_rooty() + point[1]
                widget = self.root.winfo_containing(x, y) or self.root
                log_debug(f"Drop target widget: {widget}")
            except Exception:
                log_exception("Could not resolve drop target widget")
                widget = self.root
        return widget


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


# ---------------------------------------------------------------------------
# GUI application
# ---------------------------------------------------------------------------

class App:
    def __init__(self, root):
        self.root = root
        self.root.report_callback_exception = self._report_callback_exception
        self.root.title(f"{APP_NAME} — {APP_VERSION}")
        log_debug("App initialization started")
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
        self.drop_blocks_by_widget = {}
        self.drop_manager = WindowsFileDropManager(root, self._handle_dropped_files)
        self.lookup_results = []
        self.lookup_results_lock = threading.Lock()
        self.lookup_generation = 0
        self.input_report = None
        self.undo_snapshot = None
        self.last_error_type = "None"
        self.preferences = load_preferences()
        window = self.preferences["window"]
        geometry = f"{window['width']}x{window['height']}"
        if window["x"] is not None and window["y"] is not None:
            geometry += f"{window['x']:+d}{window['y']:+d}"
        self.root.geometry(geometry)
        options = self.preferences["options"]
        self.auto_lookup_after_drop = tk.BooleanVar(value=options["auto_lookup_after_drop"])
        self.auto_lookup_pending = False
        self.dark_mode = tk.BooleanVar(value=options["dark_mode"])
        self.mac_fmt = tk.StringVar(value=options["mac_fmt"])
        self.exclude_po = tk.BooleanVar(value=options["exclude_po"])
        self.exclude_cpu = tk.BooleanVar(value=options["exclude_cpu"])
        self.only_ip = tk.BooleanVar(value=options["only_ip"])
        for key in options:
            getattr(self, key).trace_add("write", self._save_current_preferences)
        self.status_var = tk.StringVar(value="Ready")
        self.current_workspace = None
        self.previous_workspace = "resolver"

        main = ttk.Frame(root)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        appbar = ttk.Frame(main)
        appbar.pack(fill="x", pady=(0, 8))
        ttk.Label(appbar, text="SWITCHPORT RESOLVER", style="Brand.TLabel").pack(side="left", padx=(2, 20))
        self.resolver_nav = ttk.Button(appbar, text="▦  Resolver", command=lambda: self._show_workspace("resolver"))
        self.resolver_nav.pack(side="left", padx=(0, 4))
        self.tools_nav = ttk.Button(appbar, text="⌘  Tools", command=lambda: self._show_workspace("tools"))
        self.tools_nav.pack(side="left")
        self.settings_nav = ttk.Button(appbar, text="⚙  Settings", command=self._open_settings)
        self.settings_nav.pack(side="right", padx=(8, 0))
        Tooltip(self.settings_nav, "Open settings inside the app", self._palette)
        self.export_button = ttk.Button(appbar, text="Export ▾", command=self._show_export_menu)
        self.export_button.pack(side="right", padx=(0, 6))
        Tooltip(self.export_button, "Export current results as CSV or Excel", self._palette)
        self.lookup_button = ttk.Button(appbar, text="⌕  Lookup", command=self.lookup, style="Accent.TButton")
        self.lookup_button.pack(side="right", padx=(0, 6))
        Tooltip(self.lookup_button, "Correlate loaded switch MAC and router ARP tables", self._palette)
        self.clear_all_button = ttk.Button(appbar, text="Clear All", command=self.clear_all)
        self.clear_all_button.pack(side="right", padx=(0, 6))
        Tooltip(self.clear_all_button, "Clear all device inputs and results", self._palette)
        self.session_button = ttk.Button(appbar, text="Session ▾", command=self._show_session_menu)
        self.session_button.pack(side="right", padx=(0, 6))
        Tooltip(self.session_button, "Open or save an explicit session; raw inputs are never auto-saved", self._palette)
        self.session_menu = tk.Menu(root, tearoff=False)
        self.session_menu.add_command(label="Open Session…", command=self.open_session)
        self.session_menu.add_command(label="Save Session…", command=self.save_session)
        self.session_menu.add_separator()
        self.session_menu.add_command(label="Undo Clear All", command=self.undo_clear_all)
        self.export_menu = tk.Menu(root, tearoff=False)
        self.export_menu.add_command(label="Export CSV", command=self.export_csv)
        self.export_menu.add_command(label="Export Excel", command=self.export_xlsx)

        self.workspace = ttk.Frame(main)
        self.workspace.pack(fill="both", expand=True)
        self.resolver_workspace = ttk.Frame(self.workspace)

        # Draggable vertical splitter between device input and lookup results.
        self.main_splitter = tk.PanedWindow(
            self.resolver_workspace,
            orient=tk.VERTICAL,
            sashwidth=9,
            sashrelief=tk.RAISED,
            showhandle=True,
            handlesize=12,
            handlepad=24,
            opaqueresize=True,
            borderwidth=0,
        )
        self.main_splitter.pack(fill="both", expand=True, pady=(WORKSPACE_TOP_GAP, 0))

        # Notebook with device tabs.
        nb = ttk.Notebook(self.main_splitter)
        self.notebook = nb

        self.switch_blocks = []
        self.router_blocks = []

        for i in range(1, 3):
            frame = ttk.Frame(nb)
            nb.add(frame, text=f"RT{i}-ARP")
            block = self._build_device_tab(frame, is_router=True, index=i)
            self.router_blocks.append(block)

        for i in range(1, 6):
            frame = ttk.Frame(nb)
            nb.add(frame, text=f"SW{i}")
            block = self._build_device_tab(frame, is_router=False, index=i)
            self.switch_blocks.append(block)

        # Result table
        tree_frame = ttk.Frame(self.main_splitter)

        columns = ("switch", "vlan", "iface", "mac", "vendor", "ip", "router", "arp_iface")
        self.result_sort_column = "switch"
        self.result_sort_descending = False
        self.result_query = tk.StringVar()
        self.result_ip_filter = tk.StringVar(value="All rows")
        self.visible_rows = []
        result_controls = ttk.Frame(tree_frame)
        result_controls.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(2, 4))
        ttk.Label(result_controls, text="Find in results").pack(side="left", padx=(0, 6))
        search = ttk.Entry(result_controls, textvariable=self.result_query, width=25)
        self.result_search = search
        search.pack(side="left", padx=(0, 8))
        search.bind("<Escape>", lambda _event: self._clear_result_filters())
        Tooltip(search, "Search across every result column (Ctrl+F)", self._palette)
        ttk.Combobox(result_controls, textvariable=self.result_ip_filter,
                     values=("All rows", "Has IP", "No IP"), state="readonly",
                     width=11).pack(side="left", padx=(0, 8))
        ttk.Button(result_controls, text="Clear filters", command=self._clear_result_filters).pack(side="left")
        ttk.Button(result_controls, text="Input report", command=self._toggle_input_report).pack(side="right")
        self.result_count_var = tk.StringVar(value="0 results")
        ttk.Label(result_controls, textvariable=self.result_count_var, style="Muted.TLabel").pack(
            side="right", padx=(0, 12))
        self.result_query.trace_add("write", lambda *_: self._refresh_result_view())
        self.result_ip_filter.trace_add("write", lambda *_: self._refresh_result_view())
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.result_headings = dict(zip(columns, RESULT_HEADERS))
        self._update_result_headings()

        self.tree.column("switch", width=140, anchor="w")
        self.tree.column("vlan", width=60, anchor="center")
        self.tree.column("iface", width=120, anchor="w")
        self.tree.column("mac", width=160, anchor="w")
        self.tree.column("vendor", width=260, anchor="w")
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("router", width=140, anchor="w")
        self.tree.column("arp_iface", width=120, anchor="w")

        self.tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")
        hsb.grid(row=2, column=0, sticky="ew")
        self.report_frame = ttk.LabelFrame(tree_frame, text="Input report")
        self.report_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.report_text = tk.Text(self.report_frame, height=6, wrap="word", state="disabled")
        self.report_text.pack(fill="x", padx=6, pady=6)
        self.report_frame.grid_remove()
        tree_frame.rowconfigure(1, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.main_splitter.add(nb, minsize=150, stretch="always")
        self.main_splitter.add(tree_frame, minsize=120, stretch="always")

        self.tools_workspace = NetworkToolsView(
            self.workspace,
            lambda mac: lookup_vendor(mac, self.buckets, self.masks),
            self.set_status,
            self._palette,
        )
        self.settings_workspace = ttk.Frame(self.workspace)
        self._build_settings_tab(self.settings_workspace)
        self._show_workspace("resolver")

        # Status bar
        status = ttk.Label(main, textvariable=self.status_var, anchor="w")
        status.pack(fill="x", pady=(4, 0))
        self._apply_theme()
        self._register_root_drop_target()
        self._poll_drop_queue()
        self._poll_lookup_results()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self._close_app)
        self.main_splitter.bind("<ButtonRelease-1>", self._remember_splitter)
        self.root.after_idle(self._set_initial_splitter_position)
        log_debug("App initialization complete")

    def _bind_shortcuts(self):
        self.root.bind_all("<Control-l>", lambda _event: self.lookup()
                           if self.current_workspace == "resolver" else None)
        self.root.bind_all("<Control-t>", lambda _event: self._show_workspace("tools"))
        self.root.bind_all("<Control-e>", lambda _event: self._show_export_menu()
                           if self.current_workspace == "resolver" else None)
        self.root.bind_all("<Control-comma>", lambda _event: self._open_settings())
        self.root.bind_all("<Control-Shift-V>", lambda _event: self._paste_current_tab())
        self.root.bind_all("<Control-f>", self._focus_result_search)
        self.root.bind_all("<Control-s>", lambda _event: self.save_session()
                           if self.current_workspace == "resolver" else None)
        self.root.bind_all("<Control-o>", lambda _event: self.open_session()
                           if self.current_workspace == "resolver" else None)

    def _focus_result_search(self, _event=None):
        if self.current_workspace == "resolver":
            self.result_search.focus_set()
            self.result_search.select_range(0, "end")

    def _paste_current_tab(self):
        if self.resolver_workspace.winfo_ismapped():
            self._paste_into_tab(self.notebook.nametowidget(self.notebook.select()))

    def _show_workspace(self, name):
        self.resolver_workspace.pack_forget()
        self.tools_workspace.pack_forget()
        self.settings_workspace.pack_forget()
        self.current_workspace = name
        self.resolver_nav.configure(style="NavSelected.TButton" if name == "resolver" else "TButton")
        self.tools_nav.configure(style="NavSelected.TButton" if name == "tools" else "TButton")
        self.settings_nav.configure(style="NavSelected.TButton" if name == "settings" else "TButton")
        self.export_button.pack_forget()
        self.lookup_button.pack_forget()
        self.clear_all_button.pack_forget()
        self.session_button.pack_forget()
        if name == "resolver":
            self.session_button.pack(side="right", padx=(0, 6))
            self.export_button.pack(side="right", padx=(0, 6))
            self.lookup_button.pack(side="right", padx=(0, 6))
            self.clear_all_button.pack(side="right", padx=(0, 6))
        if name == "tools":
            self.tools_workspace.pack(fill="both", expand=True)
            self.set_status("Network tools ready")
        elif name == "settings":
            self.settings_workspace.pack(fill="both", expand=True)
            self.set_status("Settings")
        else:
            self.resolver_workspace.pack(fill="both", expand=True)
            self.set_status(f"{len(self.visible_rows)} of {len(self.last_rows)} row(s) displayed" if self.last_rows else "Ready")

    def _show_export_menu(self):
        self.export_menu.tk_popup(
            self.export_button.winfo_rootx(),
            self.export_button.winfo_rooty() + self.export_button.winfo_height(),
        )

    def _show_session_menu(self):
        self.session_menu.tk_popup(
            self.session_button.winfo_rootx(),
            self.session_button.winfo_rooty() + self.session_button.winfo_height(),
        )

    def _open_settings(self):
        if self.current_workspace == "settings":
            self._close_settings()
        else:
            self.previous_workspace = self.current_workspace or "resolver"
            self._show_workspace("settings")

    def _close_settings(self):
        self._show_workspace(self.previous_workspace)

    def _set_initial_splitter_position(self):
        # Start close to an even split while leaving the sash fully user-controlled.
        try:
            self.root.update_idletasks()
            height = self.main_splitter.winfo_height()
            if height > 1:
                self.main_splitter.sash_place(0, 0, int(height * self.preferences["window"]["split_ratio"]))
        except (tk.TclError, IndexError):
            pass

    def _remember_splitter(self, _event=None):
        try:
            height = self.main_splitter.winfo_height()
            if height > 1:
                ratio = self.main_splitter.sash_coord(0)[1] / height
                if 0.15 <= ratio <= 0.85:
                    self.preferences["window"]["split_ratio"] = round(ratio, 3)
                    self._save_current_preferences()
        except (tk.TclError, IndexError):
            pass

    def _close_app(self):
        try:
            if self.root.state() == "normal":
                window = self.preferences["window"]
                window.update(width=self.root.winfo_width(), height=self.root.winfo_height(),
                              x=self.root.winfo_x(), y=self.root.winfo_y())
            self._save_current_preferences()
        finally:
            self.root.destroy()

    def _report_callback_exception(self, exc_type, exc_value, exc_tb):
        self.last_error_type = exc_type.__name__
        log_exception("Unhandled Tk callback exception", exc_type, exc_value, exc_tb)
        try:
            messagebox.showerror("Error", f"Unexpected {exc_type.__name__}.\n\nOpen Settings → Team support for a sanitized diagnostic summary or local logs.")
        except Exception:
            pass

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

    def _palette(self):
        return effective_palette(self.preferences, "dark" if self.dark_mode.get() else "light")

    def _save_current_preferences(self, *_args):
        if getattr(self, "_suspend_settings_save", False):
            return
        for key in self.preferences["options"]:
            self.preferences["options"][key] = getattr(self, key).get()
        try:
            save_preferences(self.preferences)
        except OSError as exc:
            self.set_status(f"Could not save settings: {exc}")

    def _apply_theme(self):
        palette = self._palette()

        self.root.configure(bg=palette["bg"])
        set_windows_titlebar_theme(self.root, self.dark_mode.get())
        self.root.option_add("*TCombobox*Listbox.background", palette["entry_bg"])
        self.root.option_add("*TCombobox*Listbox.foreground", palette["fg"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", palette["select_bg"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", palette["select_fg"])

        if hasattr(self, "tools_workspace"):
            self.tools_workspace.apply_theme(palette)
        if hasattr(self, "export_menu"):
            self.export_menu.configure(
                background=palette["panel_bg"], foreground=palette["fg"],
                activebackground=palette["select_bg"], activeforeground=palette["select_fg"],
            )
            self.session_menu.configure(
                background=palette["panel_bg"], foreground=palette["fg"],
                activebackground=palette["select_bg"], activeforeground=palette["select_fg"],
            )

        if hasattr(self, "main_splitter"):
            self.main_splitter.configure(
                background=palette["border"],
                sashrelief=tk.RAISED,
            )

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
        self._style_configure("Brand.TLabel", background=palette["bg"], foreground=palette["fg"], font=("Segoe UI Semibold", 14))
        self._style_configure("Muted.TLabel", background=palette["bg"], foreground=palette["muted_fg"])
        self._style_configure("Value.TLabel", background=palette["bg"], foreground=palette["fg"], font=("Segoe UI Semibold", 10))
        self._style_configure("Mono.TLabel", background=palette["bg"], foreground=palette["fg"], font=("Consolas", 10))
        self._style_configure("Error.TLabel", background=palette["bg"], foreground=palette["error_fg"])
        # Tools is a single inset work surface, using the same dark-blue color
        # role as Resolver's text inputs rather than the outer window gray.
        tools_surface = palette["entry_bg"]
        self._style_configure("ToolsSurface.TFrame", background=tools_surface)
        self._style_configure("ToolsSurface.TNotebook", background=tools_surface,
                              bordercolor=palette["border"])
        self._style_configure("ToolsSurface.TLabelframe", background=tools_surface,
                              foreground=palette["fg"], bordercolor=palette["border"],
                              relief="solid")
        self._style_configure("ToolsSurface.TLabelframe.Label", background=tools_surface,
                              foreground=palette["fg"])
        self._style_configure("ToolsSurface.TLabel", background=tools_surface,
                              foreground=palette["fg"])
        self._style_configure("ToolsMuted.TLabel", background=tools_surface,
                              foreground=palette["muted_fg"])
        self._style_configure("ToolsValue.TLabel", background=tools_surface,
                              foreground=palette["fg"], font=("Segoe UI Semibold", 10))
        self._style_configure("ToolsMono.TLabel", background=tools_surface,
                              foreground=palette["fg"], font=("Consolas", 10))
        self._style_configure("ToolsError.TLabel", background=tools_surface,
                              foreground=palette["error_fg"])
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
        self._style_configure("Accent.TButton", background=palette["select_bg"], foreground=palette["select_fg"], padding=(11, 5))
        self._style_map("Accent.TButton", background=[("active", palette["button_active"]), ("pressed", palette["button_pressed"])])
        self._style_configure("NavSelected.TButton", background=palette["select_bg"], foreground=palette["select_fg"], padding=(11, 5))
        self._style_configure("Compact.TButton", background=palette["button_bg"], foreground=palette["fg"], padding=(6, 1))
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
        if hasattr(self, "report_text"):
            self.report_text.configure(background=palette["entry_bg"], foreground=palette["fg"],
                                       selectbackground=palette["select_bg"],
                                       selectforeground=palette["select_fg"],
                                       highlightbackground=palette["border"],
                                       relief="flat")

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

        clear_tab_btn = ttk.Button(
            top,
            text="Clear Tab",
            command=lambda f=frame: self._clear_tab(f)
        )
        clear_tab_btn.pack(side="left", padx=2)

        hint_text = "Paste, load, or drag/drop 'show mac address-table' output"
        if is_router:
            hint_text = "Paste, load, or drag/drop 'show ip arp' output"

        ttk.Label(top, text=hint_text).pack(side="left", padx=(10, 0))
        source_var = tk.StringVar(value="No file loaded")
        ttk.Label(top, textvariable=source_var).pack(side="right", padx=(8, 0))

        text_frame = ttk.Frame(frame)
        text_frame.pack(fill="both", expand=True)

        txt = tk.Text(text_frame, wrap="none", height=12)
        self.text_widgets.append(txt)
        txt.bind("<<Paste>>", self._on_text_paste, add="+")
        txt.bind("<Control-v>", self._on_text_paste, add="+")
        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=txt.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        txt.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)

        block = {
            "frame": frame,
            "host_var": host_var,
            "default_host": default_host,
            "txt": txt,
            "is_router": is_router,
            "source_var": source_var,
        }
        self._register_drop_target(txt, block)
        return block

    def _build_settings_tab(self, frame):
        content = ttk.Frame(frame, padding=12)
        content.pack(fill="both", expand=True)
        tabs = ttk.Notebook(content)
        tabs.pack(fill="both", expand=True)
        general = ttk.Frame(tabs, padding=12)
        colors = ttk.Frame(tabs, padding=12)
        tabs.add(general, text="General")
        tabs.add(colors, text="Colors")

        resolver = ttk.LabelFrame(general, text="Resolver", padding=12)
        resolver.pack(fill="x", pady=(0, 12))
        row = ttk.Frame(resolver)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="MAC format:").pack(side="left", padx=(0, 8))
        ttk.Combobox(row, textvariable=self.mac_fmt, values=MAC_FORMATS,
                     state="readonly", width=23).pack(side="left")
        for label, variable in (
            ("Exclude Port-Channels (Po*)", self.exclude_po),
            ("Exclude CPU MACs", self.exclude_cpu),
            ("Only rows with IP match", self.only_ip),
            ("Auto lookup after paste/load/drop", self.auto_lookup_after_drop),
        ):
            ttk.Checkbutton(resolver, text=label, variable=variable).pack(anchor="w", pady=3)

        appearance = ttk.LabelFrame(general, text="Appearance", padding=12)
        appearance.pack(fill="x", pady=(0, 12))
        ttk.Checkbutton(appearance, text="Dark mode", variable=self.dark_mode,
                        command=self._apply_theme).pack(anchor="w")
        ttk.Label(appearance, text="Customize the dark and light palettes on the Colors tab.",
                  style="Muted.TLabel").pack(anchor="w", pady=(6, 0))

        vendor_db = ttk.LabelFrame(general, text="Vendor database", padding=12)
        vendor_db.pack(fill="x", pady=(0, 12))
        db_row = ttk.Frame(vendor_db)
        db_row.pack(anchor="w")
        ttk.Button(db_row, text="Update DB", command=self.update_db).pack(side="left", padx=(0, 6))
        ttk.Button(db_row, text="Load DB File", command=self.load_db_file).pack(side="left")
        support = ttk.LabelFrame(general, text="Team support", padding=12)
        support.pack(fill="x", pady=(0, 12))
        ttk.Label(support, text="Diagnostic summaries omit raw device output, MACs, IPs, names, and file paths.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        support_row = ttk.Frame(support)
        support_row.pack(anchor="w")
        ttk.Button(support_row, text="Copy diagnostic summary",
                   command=self.copy_diagnostic_summary).pack(side="left", padx=(0, 6))
        ttk.Button(support_row, text="Open local log folder",
                   command=self.open_log_folder).pack(side="left")
        ttk.Label(general, text=f"Version: {APP_VERSION}  •  Tag: {DEVELOPER_TAG}",
                  style="Muted.TLabel").pack(anchor="w")

        top = ttk.Frame(colors)
        top.pack(fill="x", pady=(0, 10))
        ttk.Label(top, text="Edit palette:").pack(side="left", padx=(0, 8))
        self.color_theme = tk.StringVar(value="dark" if self.dark_mode.get() else "light")
        chooser = ttk.Combobox(top, textvariable=self.color_theme,
                               values=("dark", "light"), state="readonly", width=12)
        chooser.pack(side="left")
        chooser.bind("<<ComboboxSelected>>", self._switch_color_theme)
        ttk.Label(colors, text="Enter #RRGGBB values. Apply Colors updates the entire app and saves them.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))

        self.color_drafts = {theme: effective_palette(self.preferences, theme)
                             for theme in THEMES}
        self.color_vars = {}
        self.color_swatches = {}
        grid = ttk.Frame(colors)
        grid.pack(fill="x")
        split = (len(COLOR_LABELS) + 1) // 2
        for index, (key, label) in enumerate(COLOR_LABELS.items()):
            column, row_index = divmod(index, split)
            cell = ttk.Frame(grid)
            cell.grid(row=row_index, column=column, sticky="ew", padx=(0, 20), pady=5)
            ttk.Label(cell, text=label, width=21).pack(side="left")
            variable = tk.StringVar()
            self.color_vars[key] = variable
            ttk.Entry(cell, textvariable=variable, width=10).pack(side="left", padx=(2, 6))
            swatch = tk.Label(cell, text="    ", relief="solid", borderwidth=1)
            swatch.pack(side="left")
            self.color_swatches[key] = swatch
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)
        self._load_color_fields()
        self._color_theme_shown = self.color_theme.get()
        self.color_error = tk.StringVar(value="")
        ttk.Label(colors, textvariable=self.color_error, style="Error.TLabel").pack(
            anchor="w", pady=(8, 4))
        ttk.Button(colors, text="Apply Colors", style="Accent.TButton",
                   command=self._apply_color_fields).pack(anchor="w")

        footer = ttk.Frame(content)
        footer.pack(fill="x", pady=(10, 0))
        ttk.Button(footer, text="Reset All Settings to Defaults",
                   command=self._reset_preferences).pack(side="left")
        ttk.Button(footer, text="Back", command=self._close_settings).pack(side="right")

    def _store_color_fields(self):
        theme = self.color_theme.get()
        if theme in THEMES:
            self.color_drafts[theme] = {key: variable.get()
                                        for key, variable in self.color_vars.items()}

    def _load_color_fields(self):
        draft = self.color_drafts[self.color_theme.get()]
        for key, variable in self.color_vars.items():
            value = draft[key]
            variable.set(value)
            try:
                self.color_swatches[key].configure(background=normalize_color(value))
            except ValueError:
                self.color_swatches[key].configure(background=self._palette()["bg"])

    def _switch_color_theme(self, _event=None):
        # Combobox variable already names the new theme; preserve edits to the old one.
        previous = getattr(self, "_color_theme_shown", None)
        if previous in THEMES:
            self.color_drafts[previous] = {key: variable.get()
                                           for key, variable in self.color_vars.items()}
        self._color_theme_shown = self.color_theme.get()
        self._load_color_fields()
        self.color_error.set("")

    def _apply_color_fields(self):
        self._store_color_fields()
        normalized = {}
        for theme, values in self.color_drafts.items():
            normalized[theme] = {}
            for key, value in values.items():
                try:
                    color = normalize_color(value)
                except ValueError:
                    self.color_theme.set(theme)
                    self._color_theme_shown = theme
                    self._load_color_fields()
                    self.color_error.set(f"{theme.title()} / {COLOR_LABELS[key]}: use #RRGGBB.")
                    return
                if color != THEMES[theme][key]:
                    normalized[theme][key] = color
        for theme in THEMES:
            palette = {**THEMES[theme], **normalized[theme]}
            weak = [label for label, foreground, background in (
                ("main text", "fg", "bg"), ("input text", "fg", "entry_bg"),
                ("result text", "fg", "tree_bg"), ("table headings", "fg", "heading_bg"),
                ("selected text", "select_fg", "select_bg"),
            ) if contrast_ratio(palette[foreground], palette[background]) < 4.5]
            if weak and not messagebox.askyesno(
                    "Low-contrast colors",
                    f"The {theme} palette has low contrast for: {', '.join(weak)}.\n\nApply anyway?",
                    parent=self.root):
                return
        self.preferences["colors"] = normalized
        self.color_drafts = {theme: effective_palette(self.preferences, theme)
                             for theme in THEMES}
        self._color_theme_shown = self.color_theme.get()
        self._load_color_fields()
        self.color_error.set("")
        self._save_current_preferences()
        self._apply_theme()
        self.set_status("Colors saved")

    def _reset_preferences(self):
        if not messagebox.askyesno("Reset settings", "Restore all options and both color palettes to defaults?",
                                   parent=self.root):
            return
        self.preferences = default_preferences()
        self._suspend_settings_save = True
        try:
            for key, value in self.preferences["options"].items():
                getattr(self, key).set(value)
        finally:
            self._suspend_settings_save = False
        self.color_drafts = {theme: effective_palette(self.preferences, theme)
                             for theme in THEMES}
        self._color_theme_shown = self.color_theme.get()
        self._load_color_fields()
        self.color_error.set("")
        self._save_current_preferences()
        self._apply_theme()
        self.set_status("Default settings restored")

    def copy_diagnostic_summary(self):
        report = self.input_report or {}
        lines = [f"{APP_NAME} {APP_VERSION}", f"Windows: {platform.win32_ver()[0] or 'unknown'}",
                 f"Python: {platform.python_version()}; packaged: {bool(getattr(sys, 'frozen', False))}",
                 f"Last error type: {self.last_error_type}",
                 f"MAC parsed: {report.get('mac_parsed', 'not run')}",
                 f"MAC included: {report.get('mac_eligible', 'not run')}",
                 f"MAC excluded: {report.get('mac_excluded', 'not run')}",
                 f"ARP parsed: {report.get('arp_parsed', 'not run')}",
                 f"MAC matched: {report.get('mac_matched', 'not run')}",
                 f"Warnings: {report.get('warnings', 'not run')}"]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self.set_status("Sanitized diagnostic summary copied")

    def open_log_folder(self):
        path = os.path.dirname(crash_log_path())
        try:
            os.makedirs(path, exist_ok=True)
            os.startfile(path)
        except OSError as exc:
            messagebox.showerror("Logs", f"Could not open log folder:\n{exc}", parent=self.root)

    # ------------------------------------------------------------------
    # Helpers for tabs
    # ------------------------------------------------------------------

    def _register_drop_target(self, widget, block):
        self.drop_blocks_by_widget[widget] = block

    def _register_root_drop_target(self):
        self.drop_manager.register(self.root)

    def _poll_drop_queue(self):
        try:
            for files, point in self.drop_manager.pop_pending_drops():
                log_debug(f"Polling queued drop: files={len(files)} point={point}")
                widget = self.drop_manager.widget_for_drop_point(point)
                self._handle_dropped_files(widget, files)
        except Exception:
            log_exception("Error while polling queued drops")

        try:
            if self.root.winfo_exists():
                self.root.after(100, self._poll_drop_queue)
        except Exception:
            pass

    def _queue_lookup_result(self, result):
        with self.lookup_results_lock:
            self.lookup_results.append(result)

    def _pop_lookup_results(self):
        with self.lookup_results_lock:
            results = self.lookup_results[:]
            self.lookup_results = []
        return results

    def _poll_lookup_results(self):
        try:
            for result in self._pop_lookup_results():
                if not is_current_lookup_result(result, self.lookup_generation,
                                                self._collect_lookup_inputs()):
                    if result.get("generation") == self.lookup_generation:
                        self.set_status("Inputs changed during lookup; run Lookup again")
                    continue
                status = result.get("status")
                if status == "ok":
                    self._finish_lookup(result["rows"], result["inputs"],
                                        result.get("on_complete"), result["report"])
                else:
                    self.last_error_type = result.get("error_type", "LookupError")
                    self.set_status(f"Lookup failed ({self.last_error_type}); see Settings → Team support")
        except Exception:
            log_exception("Error while polling lookup results")

        try:
            if self.root.winfo_exists():
                self.root.after(50, self._poll_lookup_results)
        except Exception:
            pass

    def _find_block_by_frame(self, frame):
        for b in self.switch_blocks + self.router_blocks:
            if b["frame"] is frame:
                return b
        return None

    def _current_device_block(self):
        if not hasattr(self, "notebook"):
            return None
        try:
            selected = self.notebook.nametowidget(self.notebook.select())
        except Exception:
            return None
        return self._find_block_by_frame(selected)

    def _read_text_file(self, path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def _set_block_source(self, block, source):
        source_var = block.get("source_var")
        if source_var is not None:
            source_var.set(source or "No file loaded")

    def _load_text_into_block(self, block, content, fallback="", source=""):
        txt = block["txt"]
        txt.delete("1.0", "end")
        txt.insert("1.0", content)
        self._prefill_hostname(block, content, fallback=fallback)
        self._set_block_source(block, source)

    def _schedule_auto_lookup(self, reason):
        if not self.auto_lookup_after_drop.get():
            return
        if self.auto_lookup_pending:
            return
        self.auto_lookup_pending = True
        log_debug(f"Scheduling auto lookup after {reason}")
        self.root.after(100, self._run_scheduled_auto_lookup)

    def _run_scheduled_auto_lookup(self):
        self.auto_lookup_pending = False
        self.lookup()

    def _on_text_paste(self, event=None):
        self.root.after(150, lambda: self._schedule_auto_lookup("paste"))

    def _clear_tab(self, frame):
        block = self._find_block_by_frame(frame)
        if not block:
            return
        block["txt"].delete("1.0", "end")
        block["host_var"].set(block.get("default_host", ""))
        self._set_block_source(block, "No file loaded")
        self.set_status(f"Cleared {block.get('default_host', 'tab')}")

    def _classify_dropped_file(self, path, content):
        name = Path(path).name.lower()
        text = (content or "").lower()

        if (
            re.search(r"(^|[-_ .])arp([-_ .]|$)", name)
            or "show ip arp" in text
            or re.search(r"^\s*internet\s+\d{1,3}(?:\.\d{1,3}){3}\s+", text, re.M)
        ):
            return "arp"

        if (
            re.search(r"(^|[-_ .])mac([-_ .]|$)", name)
            or "show mac address-table" in text
            or "show mac-address-table" in text
            or "mac address table" in text
        ):
            return "mac"

        if parse_ios_arp_table(content):
            return "arp"
        if parse_ios_mac_table(content):
            return "mac"

        return ""

    def _next_drop_block(self, blocks, used_block_ids):
        for block in blocks:
            if id(block) in used_block_ids:
                continue
            if not block["txt"].get("1.0", "end").strip():
                return block
        for block in blocks:
            if id(block) not in used_block_ids:
                return block
        return blocks[0] if blocks else None

    def _block_for_drop(self, source_widget, kind, used_block_ids):
        direct_block = self._drop_block_for_widget(source_widget)
        if direct_block:
            return direct_block

        if kind == "arp":
            return self._next_drop_block(self.router_blocks, used_block_ids)
        if kind == "mac":
            return self._next_drop_block(self.switch_blocks, used_block_ids)

        current = self._current_device_block()
        if current:
            return current
        return None

    def _drop_block_for_widget(self, widget):
        current = widget
        while current:
            block = self.drop_blocks_by_widget.get(current)
            if block:
                return block
            current = getattr(current, "master", None)
        return None

    def _handle_dropped_files(self, source_widget, paths):
        log_debug(f"Handling dropped files: count={len(paths)} source_widget={source_widget}")
        loaded = 0
        failures = []
        used_block_ids = set()

        for path in paths:
            log_debug("Processing dropped file")
            if not os.path.isfile(path):
                failures.append(f"{os.path.basename(path)}: not a file")
                log_debug("Skipped dropped item: not a file")
                continue

            try:
                content = self._read_text_file(path)
            except Exception as e:
                failures.append(f"{os.path.basename(path)}: {e}")
                log_exception("Failed reading dropped file")
                continue

            kind = self._classify_dropped_file(path, content)
            log_debug(f"Classified dropped file: kind={kind or 'unknown'} size={len(content)}")
            block = self._block_for_drop(source_widget, kind, used_block_ids)
            if not block:
                failures.append(f"{os.path.basename(path)}: no matching tab")
                log_debug("No matching tab for dropped file")
                continue

            self._load_text_into_block(
                block,
                content,
                fallback=Path(path).stem,
                source=f"Loaded from file: {Path(path).name}",
            )
            log_debug(
                "Loaded dropped file into "
                f"{block.get('default_host', 'unknown')} tab"
            )
            used_block_ids.add(id(block))
            loaded += 1

        if loaded:
            self.set_status(f"Loaded {loaded} dropped file(s)")
            log_debug(f"Drop handling loaded {loaded} file(s)")
        if failures:
            log_debug(f"Drop handling failures: {len(failures)}")
            messagebox.showwarning("Drag and Drop", "Some files were not loaded:\n\n" + "\n".join(failures))
        if loaded:
            self._schedule_auto_lookup("drop")

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
        self._load_text_into_block(block, clip, source="Loaded from clipboard")
        self._schedule_auto_lookup("paste")

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
            content = self._read_text_file(p)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file:\n{e}")
            return

        self._load_text_into_block(
            block,
            content,
            fallback=Path(p).stem,
            source=f"Loaded from file: {Path(p).name}",
        )
        self._schedule_auto_lookup("file load")

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
        self.visible_rows = []
        self.input_report = None
        self.result_count_var.set("0 results")
        self._update_input_report_text()

    def _clear_result_filters(self):
        self.result_query.set("")
        self.result_ip_filter.set("All rows")

    def _update_result_headings(self):
        for column, label in self.result_headings.items():
            direction = (" ↓" if self.result_sort_descending else " ↑") if column == self.result_sort_column else ""
            self.tree.heading(column, text=label + direction,
                              command=lambda name=column: self._sort_result_column(name))

    def _sort_result_column(self, column):
        self.result_sort_descending = not self.result_sort_descending if column == self.result_sort_column else False
        self.result_sort_column = column
        self._update_result_headings()
        self._refresh_result_view()

    def _refresh_result_view(self):
        if not hasattr(self, "tree"):
            return
        self.visible_rows = filter_sort_rows(
            self.last_rows, self.result_query.get(), self.result_ip_filter.get(),
            self.result_sort_column, self.result_sort_descending)
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for index, row in enumerate(self.visible_rows):
            tag = "evenrow" if index % 2 == 0 else "oddrow"
            self.tree.insert("", "end", values=row, tags=(tag,))
        self.result_count_var.set(f"{len(self.visible_rows)} of {len(self.last_rows)} results")

    def _update_input_report_text(self):
        if not hasattr(self, "report_text"):
            return
        report = self.input_report
        lines = []
        if report:
            lines.append(f"MACs: {report['mac_parsed']} parsed, {report['mac_eligible']} included, "
                         f"{report['mac_excluded']} excluded; {report['arp_parsed']} ARP entries. "
                         f"{report['mac_matched']} MACs matched, {report['mac_unmatched']} unmatched.")
            for device in report["devices"]:
                if device["kind"] == "Switch":
                    detail = (f"{device['kind']} {device['slot']} ({device['name']}): "
                              f"{device['parsed']} parsed, {device['excluded']} excluded, "
                              f"{device['matched']} matched, {device['unmatched']} unmatched")
                elif device["kind"] == "Router":
                    detail = f"Router {device['slot']} ({device['name']}): {device['parsed']} ARP entries"
                else:
                    detail = "Notice"
                if device["warning"]:
                    detail += f" — WARNING: {device['warning']}"
                elif device.get("notice"):
                    detail += f" — {device['notice']}"
                lines.append(detail)
        else:
            lines.append("Run Lookup to see per-device parser and match counts.")
        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", "\n".join(lines))
        self.report_text.configure(state="disabled")

    def _toggle_input_report(self):
        if self.report_frame.winfo_ismapped():
            self.report_frame.grid_remove()
        else:
            self._update_input_report_text()
            self.report_frame.grid()

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

    def _lookup_empty_status(self, inputs):
        has_switch_data = any((item.get("text") or "").strip() for item in inputs["switch_inputs"])
        has_router_data = any((item.get("text") or "").strip() for item in inputs["router_inputs"])

        if has_router_data and not has_switch_data:
            arp_entries = 0
            for item in inputs["router_inputs"]:
                if (item.get("text") or "").strip():
                    arp_entries += len(parse_ios_arp_table(item.get("text") or ""))
            if arp_entries:
                entry_word = "entry" if arp_entries == 1 else "entries"
                return f"Lookup complete: {arp_entries} ARP {entry_word} loaded; waiting for switch MAC table"
            return "Lookup complete: ARP loaded; waiting for switch MAC table"
        if has_switch_data and not has_router_data and inputs["only_ip"]:
            return "MAC table loaded; waiting for ARP data"
        if has_switch_data and has_router_data:
            return "0 row(s) displayed with current filters"
        return "Load a MAC table and ARP table to correlate"

    def lookup(self):
        self._run_lookup()

    def _run_lookup(self, on_complete=None):
        # Correlate MAC tables with ARP tables across all devices.
        self.lookup_generation += 1
        generation = self.lookup_generation
        self._clear_results()
        inputs = self._collect_lookup_inputs()
        loaded_switches = sum(1 for item in inputs["switch_inputs"] if (item.get("text") or "").strip())
        loaded_routers = sum(1 for item in inputs["router_inputs"] if (item.get("text") or "").strip())
        log_debug(
            "Lookup requested: "
            f"switch_inputs={loaded_switches} router_inputs={loaded_routers} "
            f"only_ip={inputs['only_ip']}"
        )

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
                report = build_input_report(
                    inputs["switch_inputs"], inputs["router_inputs"],
                    parse_ios_mac_table, parse_ios_arp_table,
                    inputs["exclude_po"], inputs["exclude_cpu"])

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
                log_debug(f"Lookup complete: rows={len(rows)}")

                self._queue_lookup_result({
                    "status": "ok",
                    "generation": generation,
                    "rows": rows,
                    "inputs": inputs,
                    "report": report,
                    "on_complete": on_complete,
                })
            except Exception as e:
                log_exception("Lookup failed")
                self._queue_lookup_result({
                    "status": "error",
                    "generation": generation,
                    "inputs": inputs,
                    "error_type": type(e).__name__,
                })

        threading.Thread(target=run, daemon=True).start()

    def _finish_lookup(self, rows, inputs, on_complete=None, report=None):
        self.input_report = report
        self._update_input_report_text()
        self._populate_tree(rows)
        if not rows:
            self.set_status(self._lookup_empty_status(inputs))
        elif report and report["warnings"]:
            self.set_status(f"{len(rows)} results • {report['warnings']} input warning(s); open Input report")
        if on_complete:
            on_complete()

    def _populate_tree(self, rows):
        self.last_rows = rows
        self._refresh_result_view()
        self.set_status(f"{len(self.visible_rows)} of {len(rows)} row(s) displayed")

    def _sorted_export_rows(self):
        # Export exactly the rows and ordering currently shown in the results table.
        return list(self.visible_rows)

    def _safe_filename_part(self, value):
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", (value or "").strip())
        cleaned = cleaned.strip("._-")
        return cleaned or "switchport-results"

    def _export_default_filename(self, extension):
        switch_names = []
        router_names = []
        for row in self.visible_rows:
            sw = (row[0] or "").strip()
            router = (row[6] or "").strip()
            if sw and sw not in switch_names:
                switch_names.append(sw)
            if router and router not in router_names:
                router_names.append(router)

        names = switch_names or router_names
        if not names:
            base = "switchport-results"
        elif len(names) == 1:
            base = self._safe_filename_part(names[0])
        else:
            base = f"{self._safe_filename_part(names[0])}-plus-{len(names) - 1}"

        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        return f"{base}-switchport-results-{timestamp}{extension}"

    def export_csv(self):
        self._run_lookup(on_complete=self._export_current_rows)

    def _export_current_rows(self):
        # Export the current visible table, including its chosen sort order.
        if not self.visible_rows:
            messagebox.showinfo("Export CSV", "No visible results to export. Clear filters if needed.")
            return

        rows = self._sorted_export_rows()

        p = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=self._export_default_filename(".csv"),
        )
        if not p:
            return
        try:
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(CSV_HEADERS)
                for r in rows:
                    w.writerow(r)
            self.set_status(f"Exported {len(rows)} row(s) to {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV:\n{e}")

    def export_xlsx(self):
        self._run_lookup(on_complete=self._export_current_rows_xlsx)

    def _export_current_rows_xlsx(self):
        if not self.visible_rows:
            messagebox.showinfo("Export Excel", "No visible results to export. Clear filters if needed.")
            return

        rows = self._sorted_export_rows()
        headers, export_rows = prepare_xlsx_export(rows)

        p = filedialog.asksaveasfilename(
            title="Save Excel Workbook",
            defaultextension=".xlsx",
            filetypes=[("Excel workbooks", "*.xlsx"), ("All files", "*.*")],
            initialfile=self._export_default_filename(".xlsx"),
        )
        if not p:
            return

        try:
            write_xlsx_with_filters(p, export_rows, headers=headers)
            self.set_status(f"Exported {len(export_rows)} row(s) to {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export Excel workbook:\n{e}")

    def clear_all(self):
        # Keep a single in-memory undo snapshot. Raw inputs are never auto-saved.
        if not any(b["txt"].get("1.0", "end").strip() or
                   b["host_var"].get() != b["default_host"] for b in self.switch_blocks + self.router_blocks) and not self.last_rows:
            self.set_status("Nothing to clear")
            return
        if not messagebox.askyesno("Clear All", "Clear all seven device inputs and results?\n\nYou can undo this until another Clear All or session open.",
                                   parent=self.root):
            return
        self.undo_snapshot = self._session_snapshot()
        self.lookup_generation += 1
        for b in self.switch_blocks + self.router_blocks:
            b["txt"].delete("1.0", "end")
            b["host_var"].set(b.get("default_host", ""))
            self._set_block_source(b, "No file loaded")
        self._clear_results()
        self.set_status("Cleared • Session → Undo Clear All is available")

    def _session_snapshot(self):
        return {
            "switches": [{"name": b["host_var"].get(), "text": b["txt"].get("1.0", "end-1c"),
                          "source": b["source_var"].get()} for b in self.switch_blocks],
            "routers": [{"name": b["host_var"].get(), "text": b["txt"].get("1.0", "end-1c"),
                          "source": b["source_var"].get()} for b in self.router_blocks],
            "rows": list(self.last_rows), "report": self.input_report,
        }

    def _restore_snapshot(self, snapshot, source_override=None):
        self.lookup_generation += 1
        for block, item in zip(self.switch_blocks, snapshot["switches"]):
            block["txt"].delete("1.0", "end")
            block["txt"].insert("1.0", item["text"])
            block["host_var"].set(item["name"])
            self._set_block_source(block, (source_override if item["text"] else "No file loaded")
                                   or item.get("source", "No file loaded"))
        for block, item in zip(self.router_blocks, snapshot["routers"]):
            block["txt"].delete("1.0", "end")
            block["txt"].insert("1.0", item["text"])
            block["host_var"].set(item["name"])
            self._set_block_source(block, (source_override if item["text"] else "No file loaded")
                                   or item.get("source", "No file loaded"))
        self._clear_results()
        self.input_report = snapshot.get("report")
        self._update_input_report_text()
        self._populate_tree(snapshot.get("rows", []))

    def undo_clear_all(self):
        if self.undo_snapshot is None:
            self.set_status("Nothing to undo")
            return
        if any(b["txt"].get("1.0", "end").strip() for b in self.switch_blocks + self.router_blocks):
            if not messagebox.askyesno("Undo Clear All", "Undo will replace inputs entered since Clear All. Continue?",
                                       parent=self.root):
                return
        snapshot = self.undo_snapshot
        self.undo_snapshot = None
        self._restore_snapshot(snapshot)
        self.set_status("Clear All undone")

    def save_session(self):
        if not messagebox.askokcancel("Save Session",
                                      "A session file contains the raw MAC and ARP output you entered. Save it only in an approved location.",
                                      parent=self.root):
            return
        path = filedialog.asksaveasfilename(title="Save Resolver Session",
                                            defaultextension=".sprsession",
                                            filetypes=[("Resolver sessions", "*.sprsession"), ("All files", "*.*")],
                                            initialfile="switchport-session.sprsession",
                                            parent=self.root)
        if not path:
            return
        snapshot = self._session_snapshot()
        try:
            write_session(path, snapshot["switches"], snapshot["routers"])
            self.set_status(f"Session saved to {os.path.basename(path)}")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Save Session", f"Could not save session:\n{exc}", parent=self.root)

    def open_session(self):
        path = filedialog.askopenfilename(title="Open Resolver Session",
                                          filetypes=[("Resolver sessions", "*.sprsession"), ("All files", "*.*")],
                                          parent=self.root)
        if not path:
            return
        try:
            if os.path.getsize(path) > 40_000_000:
                raise ValueError("Session file is too large.")
            session = read_session(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Open Session", f"Could not open session:\n{exc}", parent=self.root)
            return
        if any(b["txt"].get("1.0", "end").strip() for b in self.switch_blocks + self.router_blocks):
            if not messagebox.askyesno("Replace inputs", "Replace the current device inputs with this session?",
                                       parent=self.root):
                return
        self.undo_snapshot = None
        self._restore_snapshot({"switches": session["switches"], "routers": session["routers"],
                                "rows": [], "report": None}, source_override="Loaded from session")
        self._show_workspace("resolver")
        self.set_status(f"Session opened: {os.path.basename(path)} • Run Lookup")

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
    setup_crash_logging()
    root = tk.Tk()
    app = App(root)
    log_debug("Entering Tk mainloop")
    try:
        root.mainloop()
    finally:
        log_debug("Tk mainloop exited")


if __name__ == "__main__":
    main()
