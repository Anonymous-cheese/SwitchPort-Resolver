# SwitchPort Resolver

Version 4.1.0

A Windows-friendly GUI tool for **multi-device MAC table parsing, ARP correlation, and OUI vendor identification**.  
Supports **5 Cisco switches** and **2 Cisco routers** simultaneously, with automatic hostname detection, offline/online vendor lookup, flexible MAC formatting, CSV export, and fast correlation of MAC → IP → Router.

---

## What's new in 4.1.0

- Resolver results can be searched across all columns, filtered by IP match, and sorted by clicking headings. CSV/Excel exports include the **visible filtered rows**.
- Input report shows parsed, excluded, matched, and unmatched counts per device, with warnings for unrecognized or unmatched data.
- Clear All asks first and has an in-memory Undo. Sessions can be explicitly saved/opened; raw device output is never auto-saved.
- Window size, position, and splitter ratio are remembered per user. The dark theme requests a matching Windows title bar where supported.
- Resolver and Tools now share aligned outer spacing and bezels; Tools uses the same darker blue work-surface color as Resolver, including custom palettes.
- Overlapping lookups cannot replace newer results. Sample parser and workflow tests guard common switch/router formats.
- Settings includes a sanitized diagnostic summary and local log-folder access; logs are stored under Local AppData rather than on the Desktop.
- Team use, data handling, and update guidance: [Team guide](docs/TEAM_GUIDE.md) and [Deployment guide](docs/DEPLOYMENT.md).

## New tools introduced in 4.1.0

- A cleaner Resolver toolbar with separate Tools and in-app Settings workspaces plus an Export menu.
- Resolver-only Lookup, Export, and Clear All actions stay out of the Tools and Settings workspaces.
- Resolver MAC formatting and filter options now live in Settings. Dark and light palettes can be customized by hex value for every color role, saved per user, or reset to defaults.
- IPv4 subnet calculator with CIDR or dotted mask input, prefix slider, classful subnet and host counts, usable range, binary details, and previous/next subnet navigation.
- IPv6 prefix calculator with expanded address, network range, address count, bit breakdown, previous/next navigation, and paged subnet planning.
- Wildcard checker for contiguous and non-contiguous masks, including an optional test IP.
- Decimal IP converter for dotted IPv4, unsigned decimal, hexadecimal, and binary representations.
- Multiline MAC formatter with a compact result list, selected-address format details, copy buttons, and offline OUI vendor lookup.

The release EXE and source are available from the GitHub Releases page. See the [team guide](docs/TEAM_GUIDE.md) before saving sessions containing device output.

---

## Improvements in 3.0.2

- Added a draggable horizontal splitter between the device input pane and the results table.

---

## Improvements in 3.0.1

- MAC-only Excel exports now use a focused five-column table with filter/sort dropdowns when no router ARP data is loaded.

---

## Improvements in 3.0

- Added Excel `.xlsx` export with filter/sort dropdowns on every column, with VLAN values written as numbers for proper sorting.
- Added default hostname-based filenames for CSV and Excel exports while still allowing the filename to be edited.
- Added Windows drag/drop loading for saved MAC table and ARP text files.
- Added per-tab loaded-source labels and a **Clear Tab** button.
- Moved router ARP tabs before switch tabs.
- Added **Auto lookup after paste/load/drop** in Settings, including ARP-only lookup status showing loaded ARP entry counts.
- Added sample MAC and ARP test files under `samples/`.
- Added crash/debug logging to help diagnose future issues (moved to Local AppData in 4.1).

---

##  Features

###  Multi-Device Parsing  
- Parse up to **5 switch MAC tables** (`show mac address-table`)  
- Parse up to **2 router ARP tables** (`show ip arp`, with or without VRF)

###  MAC ↔ ARP Correlation  
- Automatically correlate MAC entries from switches with ARP entries from routers  
- Displays:
  - Switch name  
  - VLAN  
  - Interface  
  - MAC (user-selected formatting)  
  - Vendor (OUI)  
  - IP address  
  - Router name  
  - ARP interface  

###  Intelligent Hostname Detection  
- Automatically reads device hostnames from CLI prompts in pasted text  
- Hostname fields are pre-populated with tab defaults and replaced when a real hostname is detected
- Example supported prompts:  
  ```
  00-00-SW01
  00-00-RT01#
  RTR01(config)# do show ip arp
  100-01-SW02#
  Switch01>
  ```

###  GUI-Based Workflow  
- Clean, simple Tkinter interface  
- Starts in dark mode, with the toggle available in Settings
- Tabs for all 7 devices, plus a Settings tab for occasional vendor DB actions
- Settings includes tag and app version
- Paste/output directly or load text files from SecureCRT, PuTTY, etc.

### Filters & Options  
- **MAC format selector:**  
  - As seen  
  - `AA:BB:CC:DD:EE:FF`  
  - `AAAA.BBBB.CCCC`  
- **Exclude Port-Channels (Po*)**  
- **Only show rows with ARP match**  
- **Exclude CPU MACs**  
- All filters are optional and non-destructive

### CSV and Excel export
- Export automatically refreshes the lookup first, so files use the current pasted data and resolver settings.
- Both formats include the rows visible under the in-app search/IP filter, in the current heading-sort order. Clear filters first to export all rows.
- Excel files contain a filterable table, including a focused five-column table for MAC-only data.

###  Offline + Online OUI Lookup  
- Offline lookup using Wireshark’s `manuf` database  
- Automatic online pull when needed  
- Caches results locally (`~/.oui_lookup/manuf`)

###  Windows EXE Packaging
- Built with PyInstaller as `dist/SwitchPort Resolver.exe`
- Uses `icon.ico` as the app icon
- Bundles `manuf` so vendor lookup works offline

---

##  How to Use

### 1. Paste or Load Device Outputs  
For each tab (`SW1`…`SW5`, `RT1-ARP`, `RT2-ARP`):

- Paste output from:
  ```
  show mac address-table
  show ip arp
  show ip arp vrf FVRF
  ```
- or click **Load File** to import saved text.

### 2. Adjust Options (Optional)  
- Choose your preferred MAC formatting  
- Enable/disable filters  
- Keep CPU MAC filtering and ARP-only filtering as needed

### 3. Click **Lookup** or **Export**
The results table populates with every MAC → IP correlation.

### 4. Export as CSV or Excel
Search/filter as needed, then use **Export** to refresh the lookup and save the visible results.

---

##  Example Workflows

### ➤ Troubleshooting a client on a 3-switch stack and dual routers
1. Paste MAC table from all switches (`SW1–SW3`)  
2. Paste ARP from both routers (`RT1`, `RT2`)  
3. Click **Lookup** → instantly see which switch/port and which router/IP  
4. Export CSV for documentation

### ➤ Identifying rogue devices  
- Use **OUI lookup** for unknown MAC prefixes  
- Filter for **only IP-matched entries**  
- CPU MACs excluded to reduce noise

---

## 🛠️ Requirements

- Python 3.10+  
- Windows 10/11 recommended  
- No external dependencies beyond standard libraries  
- Optional: PyInstaller to build `.exe`

---

## 📜 License

This project is licensed under the MIT License.
You are free to use, modify, and contribute to this project, provided the original license and copyright notice are included.
