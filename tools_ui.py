"""Network utilities workspace for SwitchPort Resolver."""

import ipaddress
import tkinter as tk
from tkinter import ttk

from network_tools import (
    decimal_ip_details, ipv4_binary, ipv4_details, ipv6_binary, ipv6_details,
    ipv6_subnet_page,
    mac_details, wildcard_details,
)

WORKSPACE_TOP_GAP = 10


class Tooltip:
    def __init__(self, widget, message, palette_getter):
        self.widget, self.message = widget, message
        self.palette_getter = palette_getter
        self.popup = None
        self.job = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _event=None):
        self.job = self.widget.after(600, self._show)

    def _show(self):
        if self.popup or not self.widget.winfo_exists():
            return
        self.popup = tk.Toplevel(self.widget)
        self.popup.wm_overrideredirect(True)
        self.popup.wm_geometry(f"+{self.widget.winfo_rootx() + 16}+{self.widget.winfo_rooty() + self.widget.winfo_height() + 6}")
        palette = self.palette_getter()
        tk.Label(self.popup, text=self.message, background=palette["tooltip_bg"], foreground=palette["tooltip_fg"],
                 padx=9, pady=5, relief="solid", borderwidth=1).pack()

    def _hide(self, _event=None):
        if self.job:
            self.widget.after_cancel(self.job)
            self.job = None
        if self.popup:
            self.popup.destroy()
            self.popup = None


class NetworkToolsView(ttk.Frame):
    def __init__(self, parent, vendor_lookup, status_callback, palette_getter):
        super().__init__(parent)
        self.vendor_lookup = vendor_lookup
        self.status_callback = status_callback
        self.palette_getter = palette_getter
        self.palette = None
        self.ipv4_result = None
        self.ipv6_result = None
        self._change_job = None
        self._build()

    def _build(self):
        self.tabs = ttk.Notebook(self)
        # Match the Resolver notebook's outer bezel and bottom edge.
        self.tabs.pack(fill="both", expand=True, pady=(WORKSPACE_TOP_GAP, 0))
        self._build_ipv4()
        self._build_ipv6()
        self._build_ipv6_planner()
        self._build_wildcard()
        self._build_decimal()
        self._build_mac()
        self._style_surface_widgets()

    def _style_surface_widgets(self):
        """Give every Tools container/label a scoped surface style.

        Keeping this scoped means Resolver and Settings retain their own palette
        while custom user colors continue to flow through apply_theme().
        """
        label_styles = {
            "": "ToolsSurface.TLabel",
            "TLabel": "ToolsSurface.TLabel",
            "Muted.TLabel": "ToolsMuted.TLabel",
            "Value.TLabel": "ToolsValue.TLabel",
            "Mono.TLabel": "ToolsMono.TLabel",
            "Error.TLabel": "ToolsError.TLabel",
        }

        def visit(widget):
            if isinstance(widget, ttk.Notebook):
                widget.configure(style="ToolsSurface.TNotebook")
            elif isinstance(widget, ttk.LabelFrame):
                widget.configure(style="ToolsSurface.TLabelframe")
            elif isinstance(widget, ttk.Frame):
                widget.configure(style="ToolsSurface.TFrame")
            elif isinstance(widget, ttk.Label):
                widget.configure(style=label_styles.get(widget.cget("style"), "ToolsSurface.TLabel"))
            for child in widget.winfo_children():
                visit(child)

        visit(self)

    def _page(self, title):
        page = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(page, text=title)
        return page

    def _field(self, parent, label, variable, width=24):
        box = ttk.Frame(parent)
        box.pack(side="left", padx=(0, 12))
        ttk.Label(box, text=label, style="Muted.TLabel").pack(anchor="w", pady=(0, 4))
        entry = ttk.Entry(box, textvariable=variable, width=width)
        entry.pack(anchor="w", ipady=4)
        return entry

    def _button(self, parent, text, command, tooltip=None, style=None):
        button = ttk.Button(parent, text=text, command=command, style=style or "TButton")
        button.pack(side="left", padx=(0, 8), pady=(18, 0))
        if tooltip:
            Tooltip(button, tooltip, self.palette_getter)
        return button

    def _section(self, parent, title):
        section = ttk.LabelFrame(parent, text=title, padding=12)
        section.pack(fill="x", pady=(0, 11))
        return section

    def _result_rows(self, section, labels):
        values = {}
        grid = ttk.Frame(section)
        grid.pack(fill="x")
        for row, label in enumerate(labels):
            ttk.Label(grid, text=label, style="Muted.TLabel").grid(
                row=row, column=0, sticky="w", padx=(0, 16), pady=4)
            variable = tk.StringVar(value="—")
            ttk.Label(grid, textvariable=variable, style="Value.TLabel").grid(
                row=row, column=1, sticky="w", pady=4)
            copy = ttk.Button(grid, text="Copy", width=6, style="Compact.TButton",
                              command=lambda v=variable: self._copy(v.get()))
            copy.grid(row=row, column=2, sticky="e", padx=(18, 0), pady=1)
            Tooltip(copy, f"Copy {label.lower()}", self.palette_getter)
            values[label] = variable
        grid.columnconfigure(1, weight=1)
        return values

    def _copy(self, text):
        if not text or text == "—":
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_callback("Copied to clipboard")

    def _error(self, variable, error):
        variable.set(str(error))
        self.status_callback(str(error))

    def _build_ipv4(self):
        page = self._page("IPv4 Subnet")
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 9))
        self.ipv4_address = tk.StringVar(value="10.3.3.3")
        self.ipv4_mask = tk.StringVar(value="24")
        self._field(row, "IP ADDRESS", self.ipv4_address, 27)
        self._field(row, "PREFIX OR SUBNET MASK", self.ipv4_mask, 24)
        self._button(row, "Calculate", self.calculate_ipv4, "Calculate this IPv4 subnet", "Accent.TButton")
        self.ipv4_error = tk.StringVar()
        ttk.Label(page, textvariable=self.ipv4_error, style="Error.TLabel").pack(anchor="w")

        columns = ttk.Frame(page)
        columns.pack(fill="x")
        mask_section = ttk.LabelFrame(columns, text="MASK DETAILS", padding=12)
        mask_section.pack(side="left", fill="both", expand=True, padx=(0, 6), pady=(0, 11))
        line = ttk.Frame(mask_section)
        line.pack(fill="x")
        ttk.Label(line, text="Prefix length", style="Muted.TLabel").pack(side="left", padx=(0, 10))
        ttk.Button(line, text="−", width=3, command=lambda: self._step_prefix(-1)).pack(side="left")
        self.prefix_scale = tk.Scale(line, from_=0, to=32, orient="horizontal", showvalue=False,
                                     variable=tk.IntVar(value=24), length=270, resolution=1,
                                     command=self._slide_prefix, borderwidth=0, highlightthickness=0)
        self.prefix_scale.pack(side="left", padx=8)
        ttk.Button(line, text="+", width=3, command=lambda: self._step_prefix(1)).pack(side="left")
        self.ipv4_mask_details = self._result_rows(mask_section, [
            "Address class", "Subnet mask", "Wildcard mask", "Subnet bits",
            "Maximum subnets", "Host bits", "Total addresses", "Usable hosts",
        ])

        address_section = ttk.LabelFrame(columns, text="ADDRESSES", padding=12)
        address_section.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=(0, 11))
        self.ipv4_addresses = self._result_rows(address_section, [
            "Current network", "CIDR", "First usable", "Last usable", "Broadcast", "Host range",
        ])

        detail = self._section(page, "SUBNET DETAILS")
        nav = ttk.Frame(detail)
        nav.pack(fill="x", pady=(0, 8))
        self.previous_ipv4 = ttk.Button(nav, text="← Previous subnet", command=lambda: self._move_ipv4(-1))
        self.previous_ipv4.pack(side="left")
        self.current_ipv4 = tk.StringVar(value="")
        ttk.Label(nav, textvariable=self.current_ipv4, style="Value.TLabel").pack(side="left", expand=True)
        self.next_ipv4 = ttk.Button(nav, text="Next subnet →", command=lambda: self._move_ipv4(1))
        self.next_ipv4.pack(side="right")
        ttk.Button(nav, text="Copy summary", command=self._copy_ipv4_summary).pack(side="right", padx=(0, 8))
        self.ipv4_binary = tk.StringVar()
        ttk.Label(detail, textvariable=self.ipv4_binary, style="Mono.TLabel", justify="left").pack(anchor="w")
        self.calculate_ipv4()

    def _slide_prefix(self, value):
        self.ipv4_mask.set(str(int(float(value))))
        self.calculate_ipv4()

    def _step_prefix(self, delta):
        try:
            current = int(self.ipv4_mask.get().lstrip("/"))
        except ValueError:
            current = 24
        self.ipv4_mask.set(str(max(0, min(32, current + delta))))
        self.calculate_ipv4()

    def calculate_ipv4(self):
        try:
            result = ipv4_details(self.ipv4_address.get(), self.ipv4_mask.get())
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
            self.ipv4_result = None
            self._error(self.ipv4_error, error)
            return
        self.ipv4_result = result
        self.ipv4_error.set("")
        self.ipv4_mask.set(str(result["prefix"]))
        self.prefix_scale.set(result["prefix"])
        info = {
            "Address class": f"Class {result['class']}",
            "Subnet mask": str(result["mask"]), "Wildcard mask": str(result["wildcard"]),
            "Subnet bits": str(result["subnet_bits"]) if result["subnet_bits"] is not None else "N/A",
            "Maximum subnets": f"{result['max_subnets']:,}" if result["max_subnets"] is not None else "N/A",
            "Host bits": str(result["host_bits"]), "Total addresses": f"{result['total']:,}",
            "Usable hosts": f"{result['usable']:,}",
        }
        for key, value in info.items():
            self.ipv4_mask_details[key].set(value)
        info = {
            "Current network": str(result["network"].network_address),
            "CIDR": str(result["network"]), "First usable": str(result["first"]),
            "Last usable": str(result["last"]), "Broadcast": str(result["broadcast"]),
            "Host range": f"{result['first']} – {result['last']}",
        }
        for key, value in info.items():
            self.ipv4_addresses[key].set(value)
        self.current_ipv4.set(str(result["network"]))
        self.previous_ipv4.configure(state="normal" if result["previous"] else "disabled")
        self.next_ipv4.configure(state="normal" if result["next"] else "disabled")
        self.ipv4_binary.set("\n".join([
            f"Host       {ipv4_binary(result['address'])}",
            f"Mask       {ipv4_binary(result['mask'])}",
            f"Subnet     {ipv4_binary(result['network'].network_address)}",
            f"Broadcast  {ipv4_binary(result['broadcast'])}",
        ]))
        self.status_callback(f"IPv4 subnet: {result['network']}")

    def _move_ipv4(self, direction):
        if not self.ipv4_result:
            return
        address = self.ipv4_result["previous" if direction < 0 else "next"]
        if address:
            self.ipv4_address.set(str(address))
            self.calculate_ipv4()

    def _copy_ipv4_summary(self):
        if not self.ipv4_result:
            return
        rows = [f"{key}: {value.get()}" for key, value in
                {**self.ipv4_mask_details, **self.ipv4_addresses}.items()]
        self._copy("\n".join(rows))

    def _build_ipv6(self):
        page = self._page("IPv6 Calculator")
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 8))
        self.ipv6_address = tk.StringVar(value="2001:db8:1234::1")
        self.ipv6_prefix = tk.StringVar(value="64")
        self._field(row, "IPv6 ADDRESS", self.ipv6_address, 38)
        self._field(row, "PREFIX LENGTH", self.ipv6_prefix, 13)
        self._button(row, "Calculate", self.calculate_ipv6, "Calculate this IPv6 prefix", "Accent.TButton")
        self.ipv6_error = tk.StringVar()
        ttk.Label(page, textvariable=self.ipv6_error, style="Error.TLabel").pack(anchor="w")
        details = self._section(page, "IPv6 PREFIX DETAILS")
        self.ipv6_values = self._result_rows(details, [
            "Compressed address", "Expanded address", "Network", "Prefix mask",
            "First address", "Last address", "Host bits", "Total addresses", "Address type",
        ])
        self.ipv6_bits = tk.StringVar()
        ttk.Label(page, textvariable=self.ipv6_bits, style="Mono.TLabel", justify="left").pack(anchor="w", pady=(0, 7))
        nav = ttk.Frame(page)
        nav.pack(fill="x", pady=(4, 0))
        self.previous_ipv6 = ttk.Button(nav, text="← Previous prefix", command=lambda: self._move_ipv6(-1))
        self.previous_ipv6.pack(side="left", padx=(0, 8))
        self.next_ipv6 = ttk.Button(nav, text="Next prefix →", command=lambda: self._move_ipv6(1))
        self.next_ipv6.pack(side="left", padx=(0, 8))
        ttk.Button(nav, text="Copy summary", command=self._copy_ipv6_summary).pack(side="left")
        ttk.Button(nav, text="Plan smaller prefixes →", command=self._open_ipv6_planner).pack(side="right")
        self.calculate_ipv6()

    def calculate_ipv6(self):
        try:
            result = ipv6_details(self.ipv6_address.get(), self.ipv6_prefix.get())
        except ValueError as error:
            self.ipv6_result = None
            self._error(self.ipv6_error, error)
            return
        self.ipv6_result = result
        self.ipv6_error.set("")
        self.ipv6_prefix.set(str(result["prefix"]))
        info = {
            "Compressed address": str(result["address"]), "Expanded address": result["expanded"],
            "Network": str(result["network"]), "Prefix mask": str(result["prefix_mask"]),
            "First address": str(result["first"]), "Last address": str(result["last"]),
            "Host bits": str(result["host_bits"]), "Total addresses": f"{result['total']:,}",
            "Address type": result["type"].title(),
        }
        for key, value in info.items():
            self.ipv6_values[key].set(value)
        self.ipv6_bits.set(
            f"Address  {ipv6_binary(result['address'])}\n"
            f"Mask     {ipv6_binary(result['prefix_mask'])}"
        )
        self.previous_ipv6.configure(state="normal" if result["previous"] else "disabled")
        self.next_ipv6.configure(state="normal" if result["next"] else "disabled")
        self.status_callback(f"IPv6 prefix: {result['network']}")

    def _move_ipv6(self, direction):
        if not self.ipv6_result:
            return
        address = self.ipv6_result["previous" if direction < 0 else "next"]
        if address:
            self.ipv6_address.set(str(address))
            self.calculate_ipv6()

    def _copy_ipv6_summary(self):
        if self.ipv6_result:
            self._copy("\n".join(f"{key}: {value.get()}" for key, value in self.ipv6_values.items()))

    def _build_ipv6_planner(self):
        page = self._page("IPv6 Planning")
        self.ipv6_plan_page = page
        ttk.Label(page, text="Plan child prefixes without generating the full address space.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 6))
        self.plan_parent = tk.StringVar(value="2001:db8:1234::/64")
        self.plan_child = tk.StringVar(value="68")
        self._field(row, "PARENT NETWORK", self.plan_parent, 38)
        self._field(row, "CHILD PREFIX", self.plan_child, 14)
        self._button(row, "Plan subnets", self._reset_ipv6_plan, "List smaller networks in this IPv6 range", "Accent.TButton")
        self.plan_error = tk.StringVar()
        ttk.Label(page, textvariable=self.plan_error, style="Error.TLabel").pack(anchor="w")
        box = self._section(page, "CHILD NETWORKS")
        navigation = ttk.Frame(box)
        navigation.pack(fill="x", pady=(0, 7))
        self.plan_previous = ttk.Button(navigation, text="← Previous page", command=lambda: self._page_ipv6(-1))
        self.plan_previous.pack(side="left", padx=(0, 8))
        self.plan_next = ttk.Button(navigation, text="Next page →", command=lambda: self._page_ipv6(1))
        self.plan_next.pack(side="left")
        self.plan_status = tk.StringVar()
        ttk.Label(navigation, textvariable=self.plan_status, style="Muted.TLabel").pack(side="right")
        table_frame = ttk.Frame(box)
        table_frame.pack(fill="both", expand=True)
        self.plan_tree = ttk.Treeview(table_frame, columns=("number", "network", "range"),
                                      show="headings", height=10)
        for column, label, width in (("number", "#", 75), ("network", "Child network", 340),
                                     ("range", "Address range", 620)):
            self.plan_tree.heading(column, text=label)
            self.plan_tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.plan_tree.yview)
        self.plan_tree.configure(yscrollcommand=scroll.set)
        self.plan_tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        ttk.Label(page, text="Double-click a child network to copy its CIDR.", style="Muted.TLabel").pack(anchor="w")
        self.plan_tree.bind("<Double-1>", self._copy_planned_network)
        self.plan_index = 0
        self.plan_ipv6()

    def _open_ipv6_planner(self):
        if self.ipv6_result:
            self.plan_parent.set(str(self.ipv6_result["network"]))
            self.plan_child.set(str(min(128, self.ipv6_result["prefix"] + 4)))
            self._reset_ipv6_plan()
        self.tabs.select(self.ipv6_plan_page)

    def _reset_ipv6_plan(self):
        self.plan_index = 0
        self.plan_ipv6()

    def plan_ipv6(self):
        try:
            network = ipaddress.IPv6Network(self.plan_parent.get().strip(), strict=False)
            plan = ipv6_subnet_page(network, self.plan_child.get(), self.plan_index)
        except ValueError as error:
            self._error(self.plan_error, error)
            return
        self.plan_error.set("")
        for item in self.plan_tree.get_children():
            self.plan_tree.delete(item)
        for number, child in plan["rows"]:
            first = child.network_address
            last = ipaddress.IPv6Address(int(first) + child.num_addresses - 1)
            self.plan_tree.insert("", "end", values=(number, str(child), f"{first} – {last}"))
        self.plan_status.set(f"{plan['count']:,} child networks  •  page {plan['page'] + 1:,} of {plan['pages']:,}")
        self.plan_previous.configure(state="normal" if plan["page"] > 0 else "disabled")
        self.plan_next.configure(state="normal" if plan["page"] + 1 < plan["pages"] else "disabled")
        self.status_callback(f"Planned {plan['count']:,} IPv6 child networks")

    def _page_ipv6(self, step):
        self.plan_index += step
        self.plan_ipv6()

    def _copy_planned_network(self, event):
        row = self.plan_tree.identify_row(event.y)
        if row:
            self._copy(str(self.plan_tree.item(row, "values")[1]))

    def _build_wildcard(self):
        page = self._page("Wildcard Checker")
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 8))
        self.wildcard_address = tk.StringVar(value="10.3.3.0")
        self.wildcard_mask = tk.StringVar(value="0.0.0.255")
        self.wildcard_candidate = tk.StringVar(value="10.3.3.42")
        self._field(row, "BASE IP ADDRESS", self.wildcard_address, 20)
        self._field(row, "WILDCARD MASK", self.wildcard_mask, 20)
        self._field(row, "TEST IP (OPTIONAL)", self.wildcard_candidate, 20)
        self._button(row, "Check", self.calculate_wildcard, "Check Cisco wildcard matching", "Accent.TButton")
        self.wildcard_error = tk.StringVar()
        ttk.Label(page, textvariable=self.wildcard_error, style="Error.TLabel").pack(anchor="w")
        details = self._section(page, "WILDCARD DETAILS")
        self.wildcard_values = self._result_rows(details, [
            "Match pattern", "Lowest matching IP", "Highest matching IP", "Matching addresses",
            "Inverse mask", "Equivalent CIDR", "Test IP result", "Wildcard binary",
        ])
        ttk.Label(page, text="Non-contiguous wildcards are supported; lowest and highest IPs do not imply every address between them matches.",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 8))
        ttk.Button(page, text="Copy summary", command=lambda: self._copy(
            "\n".join(f"{key}: {value.get()}" for key, value in self.wildcard_values.items()))).pack(anchor="w")
        self.calculate_wildcard()

    def calculate_wildcard(self):
        try:
            result = wildcard_details(self.wildcard_address.get(), self.wildcard_mask.get(),
                                      self.wildcard_candidate.get())
        except ValueError as error:
            self._error(self.wildcard_error, error)
            return
        self.wildcard_error.set("")
        info = {
            "Match pattern": f"{result['base']}  {result['wildcard']}",
            "Lowest matching IP": str(result["base"]),
            "Highest matching IP": str(result["upper"]),
            "Matching addresses": f"{result['count']:,}",
            "Inverse mask": str(result["mask"]),
            "Equivalent CIDR": f"{result['base']}/{result['prefix']}" if result["prefix"] is not None else "Not a contiguous subnet",
            "Test IP result": "Matches" if result["matched"] is True else
            "Does not match" if result["matched"] is False else "No test IP entered",
            "Wildcard binary": ipv4_binary(result["wildcard"]),
        }
        for key, value in info.items():
            self.wildcard_values[key].set(value)
        self.status_callback("Wildcard check complete")

    def _build_decimal(self):
        page = self._page("Decimal IP")
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 8))
        self.decimal_input = tk.StringVar(value="10.3.3.3")
        self._field(row, "DOTTED IP, UNSIGNED INTEGER, OR 0x HEX", self.decimal_input, 42)
        self._button(row, "Convert", self.calculate_decimal, "Convert an IPv4 address to other representations", "Accent.TButton")
        self.decimal_error = tk.StringVar()
        ttk.Label(page, textvariable=self.decimal_error, style="Error.TLabel").pack(anchor="w")
        details = self._section(page, "IPv4 ADDRESS FORMATS")
        self.decimal_values = self._result_rows(details, ["Dotted decimal", "Unsigned decimal", "Hexadecimal", "Binary"])
        self.calculate_decimal()

    def calculate_decimal(self):
        try:
            result = decimal_ip_details(self.decimal_input.get())
        except (ValueError, OverflowError) as error:
            self._error(self.decimal_error, error)
            return
        self.decimal_error.set("")
        for key, value in {
            "Dotted decimal": result["address"], "Unsigned decimal": result["integer"],
            "Hexadecimal": result["hex"], "Binary": result["binary"],
        }.items():
            self.decimal_values[key].set(str(value))
        self.status_callback("IPv4 conversion complete")

    def _build_mac(self):
        page = self._page("MAC Formatter + OUI")
        ttk.Label(page, text="Paste one or more MAC addresses (one per line).", style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        self.mac_input = tk.Text(page, height=5, wrap="none")
        self.mac_input.pack(fill="x")
        self.mac_input.insert("1.0", "aabb.ccdd.eeff")
        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(8, 8))
        ttk.Button(actions, text="Format + look up", command=self.calculate_macs, style="Accent.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Copy all results", command=self._copy_mac_results).pack(side="left")
        self.mac_error = tk.StringVar()
        ttk.Label(page, textvariable=self.mac_error, style="Error.TLabel").pack(anchor="w")
        self.mac_records = {}
        columns = ("input", "vendor", "oui", "assignment")
        table_frame = ttk.Frame(page)
        table_frame.pack(fill="both", expand=True, pady=(5, 10))
        self.mac_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=7)
        labels = ("Input", "Vendor", "OUI", "Assignment")
        widths = (180, 430, 140, 200)
        minimums = (120, 180, 100, 130)
        for col, label, width, minimum in zip(columns, labels, widths, minimums):
            self.mac_tree.heading(col, text=label)
            self.mac_tree.column(col, width=width, minwidth=minimum, anchor="w", stretch=True)
        vertical = ttk.Scrollbar(table_frame, orient="vertical", command=self.mac_tree.yview)
        self.mac_tree.configure(yscrollcommand=vertical.set)
        self.mac_tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        details = ttk.LabelFrame(page, text="Selected MAC — click Copy beside any value", padding=10)
        details.pack(fill="x")
        self.mac_detail_values = {}
        detail_fields = (
            ("cisco", "Cisco"), ("colon", "Colon"),
            ("colon_lower", "Lowercase"), ("hyphen", "Hyphen"),
            ("plain", "Plain"), ("oui", "OUI"),
            ("vendor", "Vendor"), ("assignment", "Assignment"),
            ("delivery", "Delivery"),
        )
        for index, (key, label) in enumerate(detail_fields):
            column, row_index = (0, index) if index < 5 else (1, index - 5)
            row = ttk.Frame(details)
            row.grid(row=row_index, column=column, sticky="ew", padx=(0, 18), pady=3)
            ttk.Label(row, text=label, width=13, style="Muted.TLabel").pack(side="left")
            value = tk.StringVar(value="—")
            self.mac_detail_values[key] = value
            ttk.Button(row, text="Copy", width=6, style="Compact.TButton",
                       command=lambda v=value: self._copy(v.get()) if v.get() != "—" else None).pack(side="right")
            ttk.Label(row, textvariable=value, style="Value.TLabel", wraplength=310).pack(
                side="left", fill="x", expand=True)
        details.columnconfigure(0, weight=1)
        details.columnconfigure(1, weight=1)
        ttk.Label(page, text="Select a row to see all formats. Double-click a table cell to copy it.",
                  style="Muted.TLabel").pack(anchor="w", pady=(8, 0))
        self.mac_tree.bind("<Double-1>", self._copy_mac_cell)
        self.mac_tree.bind("<<TreeviewSelect>>", self._show_mac_details)
        self.calculate_macs()

    def calculate_macs(self):
        for item in self.mac_tree.get_children():
            self.mac_tree.delete(item)
        self.mac_records.clear()
        self.mac_error.set("")
        lines = [line.strip() for line in self.mac_input.get("1.0", "end").splitlines() if line.strip()]
        errors = []
        for line in lines:
            try:
                result = mac_details(line, self.vendor_lookup)
            except ValueError:
                errors.append(line)
                continue
            item = self.mac_tree.insert("", "end", values=(
                result["input"], result["vendor"], result["oui"], result["assignment"],
            ))
            self.mac_records[item] = result
        if errors:
            self.mac_error.set(f"Skipped {len(errors)} invalid MAC address(es): {', '.join(errors[:2])}")
        items = self.mac_tree.get_children()
        if items:
            self.mac_tree.selection_set(items[0])
            self.mac_tree.focus(items[0])
        self._show_mac_details()
        self.status_callback(f"Formatted {len(self.mac_tree.get_children())} MAC address(es)")

    def _show_mac_details(self, _event=None):
        selection = self.mac_tree.selection()
        result = self.mac_records.get(selection[0]) if selection else None
        for key, value in self.mac_detail_values.items():
            value.set(str(result[key]) if result else "—")

    def _copy_mac_cell(self, event):
        row = self.mac_tree.identify_row(event.y)
        column = self.mac_tree.identify_column(event.x)
        if row and column:
            index = int(column[1:]) - 1
            self._copy(str(self.mac_tree.item(row, "values")[index]))

    def _copy_mac_results(self):
        fields = ("input", "cisco", "colon", "colon_lower", "hyphen", "plain",
                  "oui", "vendor", "assignment", "delivery")
        labels = ("Input", "Cisco", "Colon", "Lowercase", "Hyphen", "Plain",
                  "OUI", "Vendor", "Assignment", "Delivery")
        rows = ["\t".join(labels)]
        rows.extend("\t".join(str(self.mac_records[item][field]) for field in fields)
                    for item in self.mac_tree.get_children())
        if len(rows) > 1:
            self._copy("\n".join(rows))

    def apply_theme(self, palette):
        self.palette = palette
        if hasattr(self, "prefix_scale"):
            self.prefix_scale.configure(
                background=palette["entry_bg"], foreground=palette["fg"],
                troughcolor=palette["button_bg"], activebackground=palette["select_bg"],
            )
        if hasattr(self, "mac_input"):
            self.mac_input.configure(
                background=palette["entry_bg"], foreground=palette["fg"],
                insertbackground=palette["insert"], selectbackground=palette["select_bg"],
                selectforeground=palette["select_fg"],
                highlightbackground=palette["border"], highlightcolor=palette["select_bg"],
                relief="solid", borderwidth=1,
            )
