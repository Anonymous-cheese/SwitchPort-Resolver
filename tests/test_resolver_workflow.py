import importlib.machinery
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from resolver_workflow import (build_input_report, filter_sort_rows, is_current_lookup_result,
                               read_session, write_session)


ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("switchport_workflow_app", str(ROOT / "oui_offline.pyw"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
APP = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(APP)


class ResolverWorkflowTests(unittest.TestCase):
    def test_search_ip_filter_and_natural_sort(self):
        rows = [
            ("SW1", "10", "Gi1/0/10", "AA:BB:CC:DD:EE:FF", "Acme", "", "", ""),
            ("SW1", "10", "Gi1/0/2", "11:22:33:44:55:66", "Other", "10.0.0.2", "RT1", "Vlan10"),
            ("SW2", "20", "Gi1/0/1", "77:88:99:AA:BB:CC", "Acme", "10.0.0.10", "RT2", "Vlan20"),
        ]
        self.assertEqual([row[2] for row in filter_sort_rows(rows, sort_column="iface")],
                         ["Gi1/0/1", "Gi1/0/2", "Gi1/0/10"])
        self.assertEqual(len(filter_sort_rows(rows, "acme", "No IP")), 1)
        self.assertEqual([row[5] for row in filter_sort_rows(rows, ip_filter="Has IP", sort_column="ip")],
                         ["10.0.0.2", "10.0.0.10"])

    def test_sample_parser_counts_and_correlations(self):
        switch = (ROOT / "samples" / "sample-switch-mac.txt").read_text(encoding="utf-8")
        router = (ROOT / "samples" / "sample-router-arp.txt").read_text(encoding="utf-8")
        switch_inputs = [{"name": "SW01", "text": switch}]
        router_inputs = [{"name": "RT01", "text": router}]
        self.assertEqual(len(APP.parse_ios_mac_table(switch)), 4)
        self.assertEqual(len(APP.parse_ios_arp_table(router)), 3)
        report = build_input_report(switch_inputs, router_inputs,
                                    APP.parse_ios_mac_table, APP.parse_ios_arp_table)
        self.assertEqual((report["mac_parsed"], report["mac_eligible"], report["mac_excluded"]), (4, 3, 1))
        self.assertEqual((report["mac_matched"], report["mac_unmatched"]), (3, 0))
        rows = APP.correlate_mac_and_arp(switch_inputs, router_inputs, {}, [], exclude_po=True)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row[5] for row in rows))
        mac_only = build_input_report(switch_inputs, [], APP.parse_ios_mac_table, APP.parse_ios_arp_table)
        self.assertEqual(mac_only["warnings"], 0)
        self.assertIn("MAC-only", mac_only["devices"][-1]["notice"])

    def test_parser_variants_and_unrecognized_input_warning(self):
        mac_text = """Switch9# show mac address-table
Vlan Mac Address Type Ports
  1  aabb.ccdd.eeff DYNAMIC Gi1/0/1
 20  11:22:33:44:55:66 STATIC Gi1/0/12
 30  7788.99aa.bbcc DYNAMIC CPU
"""
        arp_text = """Router9# show ip arp vrf USERS
Protocol  Address  Age (min) Hardware Addr Type Interface
Internet 10.0.0.2 3 aabb.ccdd.eeff ARPA Vlan1
Internet 10.0.0.3 - Incomplete ARPA Vlan1
"""
        self.assertEqual(len(APP.parse_ios_mac_table(mac_text)), 3)
        self.assertEqual(len(APP.parse_ios_arp_table(arp_text)), 1)
        report = build_input_report([{"name": "SW9", "text": mac_text}, {"name": "bad", "text": "not a table"}],
                                    [{"name": "RT9", "text": arp_text}],
                                    APP.parse_ios_mac_table, APP.parse_ios_arp_table)
        self.assertEqual(report["mac_excluded"], 1)
        self.assertEqual(report["mac_matched"], 1)
        self.assertIn("No MAC entries", report["devices"][-1]["warning"])

    def test_only_latest_unchanged_lookup_may_finish(self):
        inputs = {"switch_inputs": [{"name": "SW1", "text": "table"}]}
        result = {"generation": 2, "inputs": inputs}
        self.assertTrue(is_current_lookup_result(result, 2, inputs))
        self.assertFalse(is_current_lookup_result(result, 3, inputs))
        self.assertFalse(is_current_lookup_result(result, 2, {"switch_inputs": []}))

    def test_explicit_session_roundtrip_and_validation(self):
        switches = [{"name": f"SW{i}", "text": "aabb.ccdd.eeff", "source": "clipboard"} for i in range(5)]
        routers = [{"name": f"RT{i}", "text": ""} for i in range(2)]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.sprsession"
            write_session(path, switches, routers)
            saved = read_session(path)
            self.assertEqual(saved["switches"][0], {"name": "SW0", "text": "aabb.ccdd.eeff"})
            self.assertNotIn("source", path.read_text(encoding="utf-8"))
            path.write_text(json.dumps({"format": "other", "version": 1}), encoding="utf-8")
            with self.assertRaises(ValueError):
                read_session(path)


if __name__ == "__main__":
    unittest.main()
