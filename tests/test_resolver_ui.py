import importlib.machinery
import importlib.util
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

from app_preferences import default_preferences


ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("switchport_ui_app", str(ROOT / "oui_offline.pyw"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
APP = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(APP)


class ResolverUiTests(unittest.TestCase):
    def test_lookup_filter_report_and_undo_clear(self):
        root = tk.Tk()
        try:
            with patch.object(APP, "load_preferences", return_value=default_preferences()), \
                 patch.object(APP, "save_preferences"), \
                 patch.object(APP.WindowsFileDropManager, "register"):
                app = APP.App(root)
                app.switch_blocks[0]["txt"].insert("1.0", (ROOT / "samples" / "sample-switch-mac.txt").read_text())
                app.router_blocks[0]["txt"].insert("1.0", (ROOT / "samples" / "sample-router-arp.txt").read_text())
                app.lookup()
                deadline = time.monotonic() + 3
                while not app.last_rows and time.monotonic() < deadline:
                    root.update()
                    time.sleep(0.01)
                self.assertEqual(len(app.last_rows), 3)
                self.assertEqual(app.input_report["mac_parsed"], 4)
                app.result_query.set("Gi1/0/2")
                self.assertEqual(len(app.visible_rows), 1)
                app.result_query.set("")
                app.result_ip_filter.set("No IP")
                self.assertEqual(len(app.visible_rows), 0)
                app.result_ip_filter.set("All rows")
                with patch.object(APP.messagebox, "askyesno", return_value=True):
                    app.clear_all()
                self.assertEqual(len(app.last_rows), 0)
                app.undo_clear_all()
                self.assertEqual(len(app.last_rows), 3)
                self.assertIn("aabb.ccdd.eeff", app.switch_blocks[0]["txt"].get("1.0", "end"))
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
