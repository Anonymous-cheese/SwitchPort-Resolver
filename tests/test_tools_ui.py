import tkinter as tk
import unittest

from app_preferences import THEMES
from tools_ui import NetworkToolsView


class MacFormatterUiTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")
        self.root.withdraw()
        self.view = NetworkToolsView(
            self.root, lambda _mac: "Example Vendor", lambda _status: None,
            lambda: THEMES["dark"],
        )

    def tearDown(self):
        if hasattr(self, "root"):
            self.root.destroy()

    def test_compact_list_and_full_detail_copy(self):
        self.view.mac_input.delete("1.0", "end")
        self.view.mac_input.insert("1.0", "aabb.ccdd.eeff\n0000.0c12.3456")
        self.view.calculate_macs()
        items = self.view.mac_tree.get_children()
        self.assertEqual(len(items), 2)
        self.assertEqual(self.view.mac_tree["columns"],
                         ("input", "vendor", "oui", "assignment"))
        self.assertEqual(self.view.mac_detail_values["cisco"].get(), "AABB.CCDD.EEFF")

        self.view.mac_tree.selection_set(items[1])
        self.view._show_mac_details()
        self.assertEqual(self.view.mac_detail_values["cisco"].get(), "0000.0C12.3456")
        self.assertEqual(self.view.mac_detail_values["vendor"].get(), "Example Vendor")

        copied = []
        self.view._copy = copied.append
        self.view._copy_mac_results()
        rows = copied[0].splitlines()
        self.assertEqual(len(rows), 3)
        self.assertEqual(len(rows[0].split("\t")), 10)
        self.assertIn("0000.0C12.3456", rows[2])

    def test_tools_surface_styles_and_outer_spacing(self):
        self.assertEqual(self.view.cget("style"), "ToolsSurface.TFrame")
        self.assertEqual(self.view.tabs.cget("style"), "ToolsSurface.TNotebook")
        self.assertEqual(int(self.view.tabs.pack_info()["padx"]), 0)
        page = self.view.tabs.nametowidget(self.view.tabs.tabs()[0])
        self.assertEqual(page.cget("style"), "ToolsSurface.TFrame")
        labels = [child for child in page.winfo_children() if isinstance(child, tk.Widget)
                  and child.winfo_class() == "TLabel"]
        self.assertTrue(all(label.cget("style").startswith("Tools") for label in labels))


if __name__ == "__main__":
    unittest.main()
