"""
Unit & Integration Tests for Section 5 Pre-Commit Quality Checklist.
Author: WAFBench Quality Engineering
Workspace: WAF_USTH (Nginx 1.26 + ModSecurity v3 + OWASP CRS v4.0.0)

Implements deterministic verification according to:
document/wafbench_agent_tui_guide.md (Section 5)
"""

import os
import re
import sys
import pathlib
import unittest
import subprocess

# Ensure repo root is on sys.path
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(TEST_DIR)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

from rich.console import Console
from rich.errors import MarkupError
from tui.sanitizers import safe_str, format_rule_list, FORBIDDEN_SLOP_PATTERN
from tui.renderables import (
    build_lab_header,
    build_three_state_table,
    build_three_tier_inspector,
    build_metrics_summary_panel,
)
from tui.theme import (
    BADGE_OK,
    BADGE_FAIL,
    BADGE_INVALID,
    BADGE_INCONCLUSIVE,
    BADGE_BLOCKED,
    BADGE_PASSED,
    WAFBENCH_THEME,
)


class TestZeroEmojiAudit(unittest.TestCase):
    """Checklist 1: Zero-Emoji Audit across all Python files in WAF_USTH."""

    def test_zero_emojis_in_python_code(self):
        emoji_re = re.compile(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]")
        violations = []
        for p in pathlib.Path(REPO_DIR).rglob("*.py"):
            text = p.read_text(encoding="utf-8", errors="ignore")
            matches = emoji_re.findall(text)
            if matches:
                violations.append((str(p.relative_to(REPO_DIR)), matches))
        self.assertEqual(
            violations,
            [],
            f"Emojis found in Python codebase: {violations}",
        )


class TestZeroPlaceholderAudit(unittest.TestCase):
    """Checklist 2: Zero-Placeholder & Raw HTML Audit."""

    def test_safe_str_rejection_of_forbidden_slop(self):
        """Verify that safe_str strictly raises ValueError on forbidden patterns."""
        forbidden_samples = [
            "<content>&<content>",
            "<noidung>&<noidung>",
            "[TBD]",
            "[tbd]",
            "<insert_token>",
            "<insert_payload_here>",
            "result: <foo>&<bar> extra",
        ]
        for sample in forbidden_samples:
            with self.subTest(sample=sample):
                with self.assertRaises(ValueError):
                    safe_str(sample)

    def test_safe_str_domain_fallbacks(self):
        """Verify fallback behavior for None and empty strings."""
        self.assertEqual(safe_str(None), "N/A")
        self.assertEqual(safe_str(""), "N/A")
        self.assertEqual(
            safe_str(None, fallback="Absent (RelevantOnly Policy)"),
            "Absent (RelevantOnly Policy)",
        )
        self.assertEqual(
            safe_str("", fallback="Prevented (Phase 2 Interrupt)"),
            "Prevented (Phase 2 Interrupt)",
        )

    def test_zero_raw_html_entities_in_codebase(self):
        """Assert no raw unescaped HTML entities exist across Python source files."""
        entity_re = re.compile(r"(&(?:lt|gt|amp);)")
        violations = []
        for p in pathlib.Path(REPO_DIR).rglob("*.py"):
            if "tests" in p.parts:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            matches = entity_re.findall(text)
            if matches:
                violations.append((str(p.relative_to(REPO_DIR)), matches))
        self.assertEqual(
            violations,
            [],
            f"Raw HTML entities found in Python codebase: {violations}",
        )


class TestMarkupEscapeVerification(unittest.TestCase):
    """Checklist 3: Markup Escape Verification under Rich Rendering."""

    def setUp(self):
        self.console = Console(theme=WAFBENCH_THEME, record=True, width=160)

    def test_xss_001_payload_escape_and_verbatim_rendering(self):
        """XSS-001 payload (?q=<script>alert(1)</script>) must render without tag-stripping."""
        payload = "?q=<script>alert(1)</script>"
        safe_payload = safe_str(payload)
        self.assertEqual(safe_payload, payload)

        evidence = {
            "case_id": "XSS-001",
            "run_id": "rep-1",
            "correlation_id": "a0000000-0000-0000-0000-000000000001",
            "state": "Blocking",
            "method": "GET",
            "endpoint": f"/search{payload}",
            "request_sha256": "1234567890abcdef1234567890abcdef",
            "client_status": "403 Forbidden",
            "raw_payload": payload,
            "waf_txn_id": "waf-txn-xss-001",
            "config_revision": "C0",
            "matched_rule_ids": "[941100, 949110]",
            "inbound_score": "10",
            "inbound_threshold": "5",
            "disruptive_action": "deny (403)",
            "interrupt_phase": "2",
            "audit_ref": "audit-log-01",
            "app_received": "False",
            "oracle_target": "XSS Reflected Parameter",
            "oracle_observation": "No reflection observed",
            "backend_effect": "None (Phase 2 Gateway Interrupt)",
            "reset_latency_s": "0.01",
            "validity": "VALID",
            "verdict": "TP",
            "metric_cell": "True Positive",
        }

        # Rendering must not raise MarkupError
        panel = build_three_tier_inspector(evidence)
        try:
            self.console.print(panel)
        except MarkupError as exc:
            self.fail(f"build_three_tier_inspector raised MarkupError on XSS-001: {exc}")

        output = self.console.export_text()
        self.assertIn("<script>alert(1)</script>", output, "XSS script tag was stripped from rendered output!")

    def test_sqli_001_b2_payload_escape_and_verbatim_rendering(self):
        """SQLI-001-B2 payload ({"username":"o'brien"}) must render without apostrophe corruption."""
        payload = '{"username":"o\'brien"}'
        safe_payload = safe_str(payload)
        self.assertEqual(safe_payload, payload)

        evidence = {
            "case_id": "SQLI-001-B2",
            "run_id": "rep-1",
            "correlation_id": "b0000000-0000-0000-0000-000000000002",
            "state": "DetectionOnly",
            "method": "POST",
            "endpoint": "/api/login",
            "request_sha256": "fedcba0987654321fedcba0987654321",
            "client_status": "200 OK",
            "raw_payload": payload,
            "waf_txn_id": "waf-txn-sqli-002",
            "config_revision": "C0",
            "matched_rule_ids": "[942100]",
            "inbound_score": "5",
            "inbound_threshold": "5",
            "disruptive_action": "pass",
            "interrupt_phase": "None",
            "audit_ref": "audit-log-02",
            "app_received": "True",
            "oracle_target": "PostgreSQL auth table",
            "oracle_observation": "Syntax error 42601 caught safely",
            "backend_effect": "No unauthorized row returned",
            "reset_latency_s": "0.02",
            "validity": "VALID",
            "verdict": "TN",
            "metric_cell": "True Negative",
        }

        panel = build_three_tier_inspector(evidence)
        try:
            self.console.print(panel)
        except MarkupError as exc:
            self.fail(f"build_three_tier_inspector raised MarkupError on SQLI-001-B2: {exc}")

        output = self.console.export_text()
        self.assertIn("o'brien", output, "Apostrophe payload corrupted in output!")

    def test_lab_header_and_matrix_rendering(self):
        """Verify lab header and three-state matrix render without markup error."""
        header = build_lab_header(
            {"wb-gateway": True, "wb-app": True, "wb-app-db": True},
            {"mode": "DetectionOnly", "revision": "C0", "transport": "SSH Tunnel"},
        )
        self.console.print(header)

        table = build_three_state_table([
            {
                "case_id": "SQLI-001",
                "attack_class": "SQLi",
                "label": "malicious",
                "direct_summary": "HTTP 200 (Effect Observed)",
                "detection_summary": "HTTP 200 (Score 10 / No Block)",
                "blocking_summary": "HTTP 403 (Phase 2 Block)",
                "validity": "VALID",
                "verdict": "TP",
            }
        ])
        self.console.print(table)

        summary = build_metrics_summary_panel({
            "rows": [
                {
                    "name": "Precision",
                    "formula": "TP / (TP + FP)",
                    "rate_str": "100.0%",
                    "num": "16",
                    "den": "16",
                    "attempted": "32",
                    "evaluable": "32",
                    "invalid": "0",
                    "inconclusive": "0",
                }
            ]
        })
        self.console.print(summary)

    def test_metrics_summary_panel_mock_rows_mapping(self):
        """Verify build_metrics_summary_panel maps names (DR, BR, FPR_D, FPR_B, RPR) to formulas and tallies."""
        metrics_input = {
            "rows": [
                {"name": "DR"},
                {"name": "BR"},
                {"name": "FPR_D"},
                {"name": "FPR_B"},
                {"name": "RPR"},
            ],
            "attempted": 96,
            "valid": 90,
            "invalid": 2,
            "inconclusive": 4,
            "tp_d": 12,
            "fn_d": 4,
            "tp_b": 14,
            "fn_b": 2,
            "fp_d": 1,
            "tn_d": 15,
            "fp_b": 2,
            "tn_b": 14,
            "detection_rate": 75.0,
            "blocking_rate": 87.5,
            "detection_fpr": 6.25,
            "blocking_fpr": 12.5,
        }
        panel = build_metrics_summary_panel(metrics_input)
        self.console.print(panel)
        output = self.console.export_text()

        # Check Table title
        self.assertIn("TABLE 5.2 — QUANTITATIVE EMPIRICAL METRICS SUMMARY", output)
        # Check columns (handling terminal wrapping)
        self.assertIn("Metric", output)
        self.assertIn("Formula", output)
        self.assertIn("Rate (%)", output)
        self.assertIn("Numerator", output)
        self.assertIn("Denominator", output)
        self.assertIn("Attempted", output)
        self.assertIn("Evaluable", output)
        self.assertIn("Invalid", output)
        self.assertIn("Inconcl", output)
        # Check formulas (accounting for table multi-line row wrapping)
        self.assertIn("TP_D", output)
        self.assertIn("FN_D", output)
        self.assertIn("TP_B", output)
        self.assertIn("FN_B", output)
        self.assertIn("FP_D", output)
        self.assertIn("TN_D", output)
        self.assertIn("FP_B", output)
        self.assertIn("TN_B", output)
        self.assertIn("Evaluable", output)
        self.assertIn("Units", output)
        # Check rates and tallies
        self.assertIn("75.00%", output)
        self.assertIn("87.50%", output)
        self.assertIn("6.25%", output)
        self.assertIn("12.50%", output)
        self.assertIn("Not Evaluated", output)
        self.assertIn("12 / 16", output)
        self.assertIn("14 / 16", output)
        self.assertIn("1 / 16", output)
        self.assertIn("2 / 16", output)
        self.assertIn("96 / 90 / 2", output)

    def test_metrics_summary_panel_with_real_report_metrics(self):
        """Verify build_metrics_summary_panel with real output from runner/report.py calculate_metrics()."""
        from runner.report import calculate_metrics

        mock_results = [
            {"case_id": "SQLI-001", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "TP_D"},
            {"case_id": "SQLI-002", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "FN_D"},
            {"case_id": "BENIGN-001", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "TN_D"},
            {"case_id": "BENIGN-002", "state": "DetectionOnly", "validity": "VALID", "metric_cell": "FP_D"},
            {"case_id": "SQLI-001", "state": "Blocking", "validity": "VALID", "metric_cell": "TP_B"},
            {"case_id": "SQLI-002", "state": "Blocking", "validity": "VALID", "metric_cell": "FN_B"},
            {"case_id": "BENIGN-001", "state": "Blocking", "validity": "VALID", "metric_cell": "TN_B"},
            {"case_id": "BENIGN-002", "state": "Blocking", "validity": "VALID", "metric_cell": "FP_B"},
            {"case_id": "ERR-001", "state": "Blocking", "validity": "E_HEALTH", "metric_cell": "INVALID"},
            {"case_id": "INC-001", "state": "Blocking", "validity": "I_UNSTABLE", "metric_cell": "INCONCLUSIVE"},
        ]
        real_metrics = calculate_metrics(mock_results)
        self.assertNotIn("rows", real_metrics)

        panel = build_metrics_summary_panel(real_metrics)
        self.console.print(panel)
        output = self.console.export_text()

        self.assertIn("TABLE 5.2 — QUANTITATIVE EMPIRICAL METRICS SUMMARY", output)
        self.assertIn("50.00%", output)
        self.assertIn("1 / 2", output)
        self.assertIn("10 / 8 / 1 / 1", output)
        self.assertIn("Not Evaluated", output)


class TestHeadlessExecutionVerification(unittest.TestCase):
    """Checklist 4: CLI Execution locally and over SSH."""

    @staticmethod
    def _find_wafbench():
        candidates = [
            os.path.join(REPO_DIR, "wafbench"),
            os.path.join(REPO_DIR, "..", "wafbench"),
            os.path.join(REPO_DIR, "cli.py"),
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return "wafbench"

    def test_local_cli_help(self):
        wafbench_path = self._find_wafbench()
        res = subprocess.run([wafbench_path, "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"wafbench --help failed: {res.stderr}")
        self.assertIn("WAFBench CLI", res.stdout)

    def test_local_cli_status(self):
        wafbench_path = self._find_wafbench()
        res = subprocess.run([wafbench_path, "status"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"wafbench status failed: {res.stderr}")
        self.assertTrue(
            "Container Health" in res.stdout or "WAFBENCH SYSTEM HEALTH" in res.stdout or "Pre-Flight" in res.stdout,
            f"Expected status table header not found in: {res.stdout[:200]}",
        )

    def test_remote_vm_ssh_status(self):
        if os.path.exists("/home/webadmin/WAFBench_USTH"):
            self.skipTest("Already executing on remote VM webadmin@100.66.229.98")
        cmd = ["ssh", "webadmin@100.66.229.98", "cd WAFBench_USTH && ./wafbench status"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        self.assertEqual(res.returncode, 0, f"Remote ssh wafbench status failed: {res.stderr}")
        self.assertTrue(
            "Container Health" in res.stdout or "WAFBENCH SYSTEM HEALTH" in res.stdout or "Pre-Flight" in res.stdout,
            f"Expected status table header not found in remote output: {res.stdout[:200]}",
        )


if __name__ == "__main__":
    unittest.main()
