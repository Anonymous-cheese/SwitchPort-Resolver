# SwitchPort Resolver: team guide

## Quick workflow

1. Open **Resolver**. Paste a switch `show mac address-table` into an SW tab, or use **Load File** / drag and drop. Add up to five switches. Router ARP output is optional; add up to two router outputs to correlate MACs to IPs.
2. Check the hostnames shown above each input. The app tries to infer them from command prompts or filenames; edit a name if needed.
3. Click **Lookup** (Ctrl+L). The status line shows the row count and warns when the input report needs attention.
4. Click **Input report** above results. Check each loaded device's parsed counts, exclusions, matches, and warnings. If a nonempty tab shows zero recognized entries, confirm the command/output format before trusting the results. A MAC-only lookup is valid and will report that no router ARP entries were loaded.
5. Use **Find in results** (Ctrl+F), **All rows / Has IP / No IP**, and clickable column headings to narrow and sort the table. **Clear filters** restores all rows. Export CSV or Excel from the toolbar; exports contain only the currently visible rows and refresh the lookup first.

The **Settings** workspace contains MAC format, Port-Channel/CPU exclusions, the optional "Only rows with IP match" resolver filter, automatic lookup, appearance, and vendor database actions. "Only rows with IP match" removes unmatched MACs from the result set; the table's "Has IP" view filter only hides them temporarily. To work with MAC tables without router output, turn off "Only rows with IP match."

## Sessions and safety

- **Session → Save Session** (Ctrl+S) writes a `.sprsession` JSON file containing the raw text and hostnames in all seven device tabs. Choose an approved location and treat it like a network troubleshooting record. It does not contain results; run Lookup after reopening.
- No raw MAC/ARP input is automatically saved on exit. Ordinary per-user settings save only options, colors, and window layout.
- **Session → Open Session** (Ctrl+O) replaces current inputs only after confirmation when tabs contain data.
- **Clear All** asks for confirmation. **Session → Undo Clear All** restores the last cleared inputs and results in memory, until another Clear All, opening a session, or closing the app. Undo asks again if new input would be overwritten.
- **Clear Tab** affects one device tab. It does not create a session backup.

## Troubleshooting a result

- **No rows:** Check that at least one SW tab has a MAC table. An ARP table alone cannot produce switchport rows. If "Only rows with IP match" is enabled, temporarily disable it to see unmatched MACs.
- **Unexpected missing ports:** Check the Port-Channel and CPU exclusions in Settings, then inspect the Input report's excluded counts.
- **Input warning:** A nonempty tab with zero parsed entries may be an unsupported or truncated CLI format. Keep a sanitized sample of the command output for a bug report.
- **Unexpected vendor:** The OUI database is bundled for offline use. Settings can load a local `manuf` file or update it online.
- **App problem:** Settings → **Copy diagnostic summary** copies only version, environment, aggregate counts, warning count, and error type—no hostnames, MACs, IPs, file paths, or pasted output. Review anything before sharing. **Open local log folder** opens per-user logs under Local AppData; those files may contain local stack paths and should be reviewed before sharing.

## Keyboard and display

- Ctrl+L: Lookup (Resolver only)
- Ctrl+F: focus result search; Escape there clears result filters
- Ctrl+E: Export menu (Resolver only)
- Ctrl+O / Ctrl+S: open/save session (Resolver only)
- Ctrl+T: Tools; Ctrl+,: Settings; Ctrl+Shift+V: paste into current device tab
- Tab and Shift+Tab move among controls. Treeview rows support arrow-key selection. Results headings are clickable for sorting.
- Settings → Colors accepts `#RRGGBB` values for dark/light palettes and warns before applying low-contrast combinations. **Reset All Settings to Defaults** resets options, colors, and remembered layout.

The app is designed for local use. It does not send pasted CLI output to a service. **Update DB** retrieves only the Wireshark OUI vendor file when you request it.
