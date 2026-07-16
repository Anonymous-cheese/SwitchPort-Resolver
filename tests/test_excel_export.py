import importlib.machinery
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader("switchport_resolver", str(ROOT / "oui_offline.pyw"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
APP = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(APP)

XML_NS = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


class ExcelExportTests(unittest.TestCase):
    def _table_details(self, rows):
        headers, export_rows = APP.prepare_xlsx_export(rows)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "export.xlsx"
            APP.write_xlsx_with_filters(path, export_rows, headers=headers)
            with zipfile.ZipFile(path) as workbook:
                table_xml = ElementTree.fromstring(workbook.read("xl/tables/table1.xml"))

        auto_filter = table_xml.find("x:autoFilter", XML_NS)
        columns = table_xml.find("x:tableColumns", XML_NS)
        return headers, export_rows, table_xml.attrib["ref"], auto_filter.attrib["ref"], columns.attrib["count"]

    def test_mac_only_export_is_a_filterable_five_column_table(self):
        rows = [
            ("SW1", "10", "Gi1/0/1", "AA:BB:CC:DD:EE:FF", "Example", "", "", ""),
            ("SW1", "20", "Gi1/0/2", "11:22:33:44:55:66", "Example", "", "", ""),
        ]

        headers, export_rows, table_ref, filter_ref, column_count = self._table_details(rows)

        self.assertEqual(headers, APP.RESULT_HEADERS[:5])
        self.assertTrue(all(len(row) == 5 for row in export_rows))
        self.assertEqual(table_ref, "A1:E3")
        self.assertEqual(filter_ref, table_ref)
        self.assertEqual(column_count, "5")

    def test_arp_export_keeps_all_filterable_columns(self):
        rows = [
            (
                "SW1", "10", "Gi1/0/1", "AA:BB:CC:DD:EE:FF", "Example",
                "10.0.0.10", "RT1", "Vlan10",
            ),
        ]

        headers, export_rows, table_ref, filter_ref, column_count = self._table_details(rows)

        self.assertEqual(headers, APP.RESULT_HEADERS)
        self.assertTrue(all(len(row) == 8 for row in export_rows))
        self.assertEqual(table_ref, "A1:H2")
        self.assertEqual(filter_ref, table_ref)
        self.assertEqual(column_count, "8")


if __name__ == "__main__":
    unittest.main()
