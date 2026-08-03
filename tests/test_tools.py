import unittest
import os
import json
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.tools import parse_logs, check_ip_reputation
from agent.deception import deploy_canary, check_canary_hits
from agent.containment import generate_containment_plan


class TestLogParsing(unittest.TestCase):
    def test_missing_log_file_returns_error_not_crash(self):
        result = parse_logs(log_path="logs/this_file_does_not_exist.log")
        self.assertIn("error", result)
        self.assertEqual(result["total_events"], 0)

    def test_parse_logs_handles_malformed_lines(self):
        test_path = "logs/test_malformed.log"
        with open(test_path, "w") as f:
            f.write("this is not valid json at all\n")
            f.write('2026-01-01 | {"event_type": "normal_access", "ip": "1.2.3.4"}\n')

        result = parse_logs(log_path=test_path, last_n=10)
        self.assertEqual(result["total_events"], 1)
        self.assertEqual(result["skipped_malformed_lines"], 1)

        os.remove(test_path)


class TestIPReputation(unittest.TestCase):
    def test_local_ip_returns_safe_mock_response(self):
        result = check_ip_reputation("127.0.0.1")
        self.assertTrue(result["is_local_test"])
        self.assertEqual(result["abuse_score"], 0)


class TestDeception(unittest.TestCase):
    def test_deploy_canary_creates_valid_record(self):
        result = deploy_canary(trigger_reason="unit test", canary_type="fake_credential")
        self.assertEqual(result["status"], "deployed")
        self.assertIn("canary_id", result)
        self.assertFalse(result["details"]["hit"])

    def test_check_canary_hits_returns_expected_structure(self):
        result = check_canary_hits()
        self.assertIn("total_deployed", result)
        self.assertIn("hits", result)
        self.assertIn("pending", result)


class TestContainment(unittest.TestCase):
    def test_generate_containment_plan_structure(self):
        plan = generate_containment_plan(
            ip_address="203.0.113.99",
            severity="active_exploitation",
            evidence_summary="unit test evidence"
        )
        self.assertEqual(plan["target_ip"], "203.0.113.99")
        self.assertTrue(plan["requires_human_approval"])
        self.assertIn("iptables", plan["commands"])
        self.assertIn("aws_security_group", plan["commands"])

    def test_recon_severity_gets_different_recommendations(self):
        plan = generate_containment_plan(
            ip_address="203.0.113.100",
            severity="recon",
            evidence_summary="unit test recon"
        )
        self.assertNotEqual(plan["patch_recommendations"], [])


if __name__ == "__main__":
    unittest.main()