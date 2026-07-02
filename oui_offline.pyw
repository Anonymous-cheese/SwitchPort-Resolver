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
from pathlib import Path
from xml.sax.saxutils import escape

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
CACHE_DIR = os.path.join(Path.home(), ".oui_lookup")
CACHE_FILE = os.path.join(CACHE_DIR, "manuf")
APP_NAME = "SwitchPort Resolver"
APP_VERSION = "3.0"
DEVELOPER_TAG = "746f617374"
RESULT_HEADERS = ("Switch", "VLAN", "Interface", "MAC", "Vendor", "IP", "Router", "ARP Interface")
CSV_HEADERS = ("Switch", "VLAN", "Interface", "MAC", "Vendor", "IP", "Router", "ARP_Interface")
CRASH_LOG_NAME = "SwitchPort Resolver Crash Log.txt"

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
    return os.path.join(desktop_path(), CRASH_LOG_NAME)


def log_debug(message):
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        path = crash_log_path()
        with open(path, "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def log_exception(prefix, exc_type=None, exc_value=None, exc_tb=None):
    if exc_type is None:
        exc_type, exc_value, exc_tb = sys.exc_info()
    details = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log_debug(f"{prefix}\n{details}")


def setup_crash_logging():
    global _LOG_FILE_HANDLE

    log_debug("")
    log_debug("=" * 80)
    log_debug(f"{APP_NAME} {APP_VERSION} starting")
    log_debug(f"Executable: {sys.executable}")
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
            log_debug(f"Dropped file[{index}]: {buf.value}")
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
        self.root.report_callback_exception = self._report_callback_exception
        self.root.title(APP_NAME)
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
        self.auto_lookup_after_drop = tk.BooleanVar(value=True)
        self.auto_lookup_pending = False
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
        ttk.Button(opt_row, text="Export Excel", command=self.export_xlsx).pack(side="left", padx=2)
        ttk.Button(opt_row, text="Clear All", command=self.clear_all).pack(side="left", padx=(12, 0))

        # Notebook with device tabs and occasional settings.
        nb = ttk.Notebook(main)
        nb.pack(fill="both", expand=True, pady=(4, 6))
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
        self._register_root_drop_target()
        self._poll_drop_queue()
        self._poll_lookup_results()
        log_debug("App initialization complete")

    def _report_callback_exception(self, exc_type, exc_value, exc_tb):
        log_exception("Unhandled Tk callback exception", exc_type, exc_value, exc_tb)
        try:
            messagebox.showerror("Error", f"Unexpected error:\n{exc_value}\n\nDetails were written to:\n{crash_log_path()}")
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
        ttk.Checkbutton(
            appearance,
            text="Auto lookup after paste/load/drop",
            variable=self.auto_lookup_after_drop
        ).pack(anchor="w", padx=8, pady=(0, 8))

        vendor_db = ttk.LabelFrame(content, text="Vendor Database")
        vendor_db.pack(anchor="nw", fill="x", pady=(0, 8))
        db_row = ttk.Frame(vendor_db)
        db_row.pack(anchor="w", padx=8, pady=8)
        ttk.Button(db_row, text="Update DB", command=self.update_db).pack(side="left", padx=(0, 6))
        ttk.Button(db_row, text="Load DB File", command=self.load_db_file).pack(side="left")

        credits = ttk.LabelFrame(content, text="Info")
        credits.pack(anchor="nw", fill="x")
        ttk.Label(credits, text=f"Tag: {DEVELOPER_TAG}").pack(anchor="w", padx=8, pady=(8, 2))
        ttk.Label(credits, text=f"Version: {APP_VERSION}").pack(anchor="w", padx=8, pady=(2, 8))

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
                status = result.get("status")
                if status == "ok":
                    self._finish_lookup(result["rows"], result["inputs"], result.get("on_complete"))
                else:
                    self.set_status(f"Error: {result.get('error', 'lookup failed')}")
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
            log_debug(f"Processing dropped path: {path}")
            if not os.path.isfile(path):
                failures.append(f"{os.path.basename(path)}: not a file")
                log_debug(f"Skipped dropped path, not a file: {path}")
                continue

            try:
                content = self._read_text_file(path)
            except Exception as e:
                failures.append(f"{os.path.basename(path)}: {e}")
                log_exception(f"Failed reading dropped file: {path}")
                continue

            kind = self._classify_dropped_file(path, content)
            log_debug(f"Classified dropped file: {path} kind={kind or 'unknown'} size={len(content)}")
            block = self._block_for_drop(source_widget, kind, used_block_ids)
            if not block:
                failures.append(f"{os.path.basename(path)}: no matching tab")
                log_debug(f"No matching tab for dropped file: {path}")
                continue

            self._load_text_into_block(
                block,
                content,
                fallback=Path(path).stem,
                source=f"Loaded from file: {Path(path).name}",
            )
            log_debug(
                "Loaded dropped file into "
                f"{block.get('default_host', 'unknown')} tab; hostname={block['host_var'].get()}"
            )
            used_block_ids.add(id(block))
            loaded += 1

        if loaded:
            self.set_status(f"Loaded {loaded} dropped file(s)")
            log_debug(f"Drop handling loaded {loaded} file(s)")
        if failures:
            log_debug("Drop handling failures: " + "; ".join(failures))
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
                    "rows": rows,
                    "inputs": inputs,
                    "on_complete": on_complete,
                })
            except Exception as e:
                log_exception("Lookup failed")
                self._queue_lookup_result({
                    "status": "error",
                    "error": str(e),
                })

        threading.Thread(target=run, daemon=True).start()

    def _finish_lookup(self, rows, inputs, on_complete=None):
        self._populate_tree(rows)
        if not rows:
            self.set_status(self._lookup_empty_status(inputs))
        if on_complete:
            on_complete()

    def _populate_tree(self, rows):
        self.last_rows = rows
        for index, r in enumerate(rows):
            tag = "evenrow" if index % 2 == 0 else "oddrow"
            self.tree.insert("", "end", values=r, tags=(tag,))
        self.set_status(f"{len(rows)} row(s) displayed")

    def _sorted_export_rows(self):
        # Sort by Switch (hostname), then Interface numerically.
        return sorted(
            self.last_rows,
            key=lambda r: ((r[0] or ""), iface_sort_key(r[2] or ""))
        )

    def _safe_filename_part(self, value):
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", (value or "").strip())
        cleaned = cleaned.strip("._-")
        return cleaned or "switchport-results"

    def _export_default_filename(self, extension):
        switch_names = []
        router_names = []
        for row in self.last_rows:
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
        # Export current table to a CSV file, sorted by Hostname then Interface.
        if not self.last_rows:
            messagebox.showinfo("Export CSV", "No data to export.")
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
        if not self.last_rows:
            messagebox.showinfo("Export Excel", "No data to export.")
            return

        rows = self._sorted_export_rows()

        p = filedialog.asksaveasfilename(
            title="Save Excel Workbook",
            defaultextension=".xlsx",
            filetypes=[("Excel workbooks", "*.xlsx"), ("All files", "*.*")],
            initialfile=self._export_default_filename(".xlsx"),
        )
        if not p:
            return

        try:
            write_xlsx_with_filters(p, rows)
            self.set_status(f"Exported {len(rows)} row(s) to {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export Excel workbook:\n{e}")

    def clear_all(self):
        # Clear all text inputs and table.
        for b in self.switch_blocks + self.router_blocks:
            b["txt"].delete("1.0", "end")
            b["host_var"].set(b.get("default_host", ""))
            self._set_block_source(b, "No file loaded")
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
    setup_crash_logging()
    root = tk.Tk()
    app = App(root)
    root.geometry("1200x800")
    log_debug("Entering Tk mainloop")
    try:
        root.mainloop()
    finally:
        log_debug("Tk mainloop exited")


if __name__ == "__main__":
    main()
