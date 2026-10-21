import ipaddress
import unittest

from network_tools import (
    decimal_ip_details, ipv4_details, ipv6_details, ipv6_subnet_page, mac_details,
    wildcard_details,
)


class NetworkToolsTests(unittest.TestCase):
    def test_boson_ipv4_example_and_navigation(self):
        result = ipv4_details("10.3.3.3", "24")
        self.assertEqual(str(result["network"]), "10.3.3.0/24")
        self.assertEqual(str(result["first"]), "10.3.3.1")
        self.assertEqual(str(result["last"]), "10.3.3.254")
        self.assertEqual(result["subnet_bits"], 16)
        self.assertEqual(result["max_subnets"], 65536)
        self.assertEqual(str(result["previous"]), "10.3.2.0")
        self.assertEqual(str(result["next"]), "10.3.4.0")

    def test_ipv4_edge_prefixes_and_mask_input(self):
        self.assertEqual(ipv4_details("192.0.2.4", "255.255.255.254")["usable"], 2)
        self.assertEqual(ipv4_details("192.0.2.4/32")["usable"], 1)
        self.assertIsNone(ipv4_details("0.0.0.0/0")["previous"])
        self.assertIsNone(ipv4_details("255.255.255.255/32")["next"])

    def test_ipv6_network_and_navigation(self):
        result = ipv6_details("2001:db8:1234::1/64")
        self.assertEqual(str(result["network"]), "2001:db8:1234::/64")
        self.assertEqual(str(result["next"]), "2001:db8:1234:1::")
        self.assertEqual(result["host_bits"], 64)
        self.assertEqual(result["total"], 2 ** 64)
        self.assertEqual(result["type"], "documentation")
        self.assertEqual(ipv6_details("fc00::1/64")["type"], "unique local")

    def test_ipv6_subnet_planning_is_bounded(self):
        parent = ipaddress.IPv6Network("2001:db8::/32")
        plan = ipv6_subnet_page(parent, 48, page=1)
        self.assertEqual(plan["count"], 65536)
        self.assertEqual(plan["pages"], 8192)
        self.assertEqual(plan["rows"][0][1], ipaddress.IPv6Network("2001:db8:8::/48"))
        with self.assertRaises(ValueError):
            ipv6_subnet_page(parent, 31)

    def test_wildcard_noncontiguous_matching(self):
        match = wildcard_details("10.2.3.4", "0.0.0.254", "10.2.3.100")
        miss = wildcard_details("10.2.3.4", "0.0.0.254", "10.2.3.101")
        self.assertTrue(match["matched"])
        self.assertFalse(miss["matched"])
        self.assertIsNone(match["prefix"])
        self.assertEqual(match["count"], 128)

    def test_decimal_roundtrip(self):
        dotted = decimal_ip_details("10.3.3.3")
        self.assertEqual(decimal_ip_details(str(dotted["integer"]))["address"], dotted["address"])
        self.assertEqual(decimal_ip_details(dotted["hex"])["address"], dotted["address"])
        with self.assertRaises(ipaddress.AddressValueError):
            decimal_ip_details("4294967296")

    def test_mac_formats_and_vendor_lookup(self):
        result = mac_details("aabb.ccdd.eeff", lambda _mac: "Example Vendor")
        self.assertEqual(result["colon"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result["hyphen"], "AA-BB-CC-DD-EE-FF")
        self.assertEqual(result["oui"], "AA:BB:CC")
        self.assertEqual(result["vendor"], "Example Vendor")
        self.assertEqual(result["assignment"], "Locally administered")
        with self.assertRaises(ValueError):
            mac_details("aa:bb:cc", lambda _mac: "")


if __name__ == "__main__":
    unittest.main()
