#!/usr/bin/env python3
"""Regression tests for FortiGate hardening result semantics."""

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

MODULE_PATH = Path(__file__).with_name("fortigate_check.py")
SPEC = importlib.util.spec_from_file_location("fortigate_check", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def endpoint(data):
    return {"ok": True, "endpoint": "/test", "http_status": 200, "data": {"results": data}}


class ScannerTests(unittest.TestCase):
    def scanner(self):
        args = SimpleNamespace(host="192.0.2.1", port=443, vdom="root", baseline="8.0",
                               timeout=5, verify_tls=False, report="/tmp/report", evidence="/tmp/evidence")
        return MODULE.Scanner(args, "test-token")

    def by_id(self, scanner, control_id):
        return [item for item in scanner.results if item["control_id"] == control_id]

    def test_missing_is_not_disabled(self):
        self.assertFalse(MODULE.disabled(None))

    def test_missing_global_field_is_review(self):
        scanner = self.scanner()
        scanner.data["global"] = endpoint({"strong-crypto": "enable"})
        scanner.check_global(MODULE.BASELINES["8.0"])
        self.assertEqual(self.by_id(scanner, "FG-CRYPTO-002")[0]["status"], "REVIEW")
        self.assertEqual(self.by_id(scanner, "FG-PHYS-002"), [])

    def test_unavailable_protocol_endpoints_are_review(self):
        scanner = self.scanner()
        for key in ("snmp_info", "ldap", "radius", "ospf"):
            scanner.data[key] = {"ok": False, "error": "HTTP 403"}
        scanner.check_encrypted_protocols()
        for control_id in ("FG-ENC-004", "FG-ENC-001", "FG-ENC-003", "FG-ENC-006"):
            self.assertEqual(self.by_id(scanner, control_id)[0]["status"], "REVIEW")

    def test_unavailable_policy_and_vpn_endpoints_are_review(self):
        scanner = self.scanner()
        scanner.data["policies"] = {"ok": False, "error": "HTTP 403"}
        scanner.data["ssl_vpn"] = {"ok": False, "error": "HTTP 403"}
        scanner.data["ipsec"] = {"ok": False, "error": "HTTP 403"}
        scanner.check_policies()
        scanner.check_vpn()
        self.assertEqual(self.by_id(scanner, "API-POLICIES")[0]["status"], "REVIEW")
        self.assertEqual(self.by_id(scanner, "FG-VPN-005")[0]["status"], "REVIEW")
        self.assertEqual(self.by_id(scanner, "FG-VPN-007")[0]["status"], "REVIEW")

    def test_dos_requires_each_recommended_anomaly(self):
        scanner = self.scanner()
        scanner.data["dos"] = endpoint([{
            "policyid": 1,
            "status": "enable",
            "anomaly": [{"name": name, "status": "enable", "log": "enable"}
                        for name in MODULE.DOS_ANOMALIES],
        }])
        scanner.check_dos()
        self.assertEqual(self.by_id(scanner, "FG-DOS-001")[0]["status"], "PASS")
        self.assertTrue(all(self.by_id(scanner, f"FG-DOS-{name}")[0]["status"] == "PASS"
                            for name in MODULE.DOS_ANOMALIES))
        self.assertEqual(self.by_id(scanner, "FG-DOS-LOG")[0]["status"], "PASS")

    def test_broad_local_in_source_fails(self):
        scanner = self.scanner()
        scanner.data["local_in"] = endpoint([{
            "policyid": 1, "status": "enable", "action": "accept",
            "srcaddr": [{"name": "all"}], "logtraffic": "disable",
        }])
        scanner.check_local_in()
        self.assertEqual(self.by_id(scanner, "FG-LIN-003")[0]["status"], "FAIL")
        self.assertEqual(self.by_id(scanner, "FG-LIN-005")[0]["status"], "FAIL")

    def test_license_false_flag_does_not_trigger_failure(self):
        scanner = self.scanner()
        scanner.data["license"] = endpoint({"status": "valid", "invalid": False})
        scanner.check_fortiguard()
        self.assertEqual(self.by_id(scanner, "FG-FGD-001")[0]["status"], "PASS")

    def test_complete_unavailable_scan_has_no_passes(self):
        scanner = self.scanner()
        scanner.data = {key: {"ok": False, "error": "HTTP 403"} for key in MODULE.ENDPOINTS}
        scanner.run_checks()
        self.assertFalse(any(item["status"] == "PASS" for item in scanner.results))
        self.assertTrue(all(item["status"] == "REVIEW" for item in scanner.results))


if __name__ == "__main__":
    unittest.main()
