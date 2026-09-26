import json
import unittest

from workbench.adapters import (
    MAX_OUTPUT_BYTES,
    parse_nuclei_jsonl,
    parse_scanner_output,
    parse_semgrep_json,
    parse_trivy_json,
)

ASSET = "asset:test-project"


class AdapterParserTests(unittest.TestCase):
    def test_semgrep_minimizes_source_content_and_stays_candidate(self):
        raw = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.exec-used",
                        "path": "app/main.py",
                        "start": {"line": 10},
                        "end": {"line": 10},
                        "extra": {
                            "message": "Dynamic execution",
                            "severity": "ERROR",
                            "fingerprint": "abc",
                            "lines": "exec(user_input)",
                            "metavars": {"$X": {"abstract_content": "user_input"}},
                        },
                    }
                ],
                "paths": {"scanned": ["app/main.py", "app/util.py"]},
                "errors": [],
            }
        )
        result = parse_semgrep_json(raw, version="1.163.0", asset_key=ASSET)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["coverage"]["objects_tested"], 2)
        finding = result["findings"][0]
        self.assertEqual(finding["verification"], "candidate")
        self.assertEqual(finding["severity"], "medium")
        serialized = json.dumps(finding)
        self.assertNotIn("exec(user_input)", serialized)
        self.assertNotIn("abstract_content", serialized)
        self.assertFalse(finding["evidence"]["source_snippet_included"])

    def test_semgrep_errors_force_partial_coverage(self):
        result = parse_semgrep_json(
            json.dumps(
                {
                    "results": [],
                    "paths": {"scanned": ["a.py"]},
                    "errors": [{"message": "parse failed"}],
                }
            ),
            version="1.0",
            asset_key=ASSET,
        )
        self.assertEqual(result["status"], "partial")
        self.assertIn("1 error", result["error"])

    def test_semgrep_rejects_bad_shape(self):
        with self.assertRaises(ValueError):
            parse_semgrep_json("[]", version="1", asset_key=ASSET)
        with self.assertRaises(ValueError):
            parse_semgrep_json("{", version="1", asset_key=ASSET)

    def test_trivy_vulnerability_is_minimized(self):
        raw = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Class": "lang-pkgs",
                        "Type": "pip",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-1234",
                                "PkgName": "demo",
                                "InstalledVersion": "1.0",
                                "FixedVersion": "1.1",
                                "Severity": "HIGH",
                                "Title": "Example vulnerability",
                                "Description": "very long advisory",
                            }
                        ],
                    }
                ],
            }
        )
        result = parse_trivy_json(raw, version="0.68.0", asset_key=ASSET)
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["verification"], "candidate")
        self.assertEqual(finding["evidence"]["package"], "demo")
        self.assertNotIn("Description", json.dumps(finding))

    def test_trivy_secret_never_retains_match_or_code(self):
        raw = json.dumps(
            {
                "Results": [
                    {
                        "Target": "config.env",
                        "Secrets": [
                            {
                                "RuleID": "aws-access-key",
                                "Title": "AWS key",
                                "Severity": "CRITICAL",
                                "StartLine": 2,
                                "EndLine": 2,
                                "Match": "AKIA-REAL-SECRET",
                                "Code": {
                                    "Lines": [{"Content": "AWS_KEY=AKIA-REAL-SECRET"}]
                                },
                            }
                        ],
                    }
                ],
            }
        )
        result = parse_trivy_json(raw, version="0.68.0", asset_key=ASSET)
        finding = result["findings"][0]
        serialized = json.dumps(finding)
        self.assertNotIn("AKIA-REAL-SECRET", serialized)
        self.assertFalse(finding["evidence"]["secret_value_included"])
        self.assertFalse(finding["evidence"]["embedded_code_included"])

    def test_trivy_misconfig_omits_embedded_code(self):
        raw = json.dumps(
            {
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Misconfigurations": [
                            {
                                "ID": "DS001",
                                "Title": "Bad config",
                                "Severity": "MEDIUM",
                                "Resolution": "Use safe config",
                                "CauseMetadata": {
                                    "Resource": "Dockerfile",
                                    "StartLine": 4,
                                    "EndLine": 5,
                                    "Code": {"Lines": [{"Content": "password=secret"}]},
                                },
                            }
                        ],
                    }
                ],
            }
        )
        result = parse_trivy_json(raw, version="0.68.0", asset_key=ASSET)
        serialized = json.dumps(result)
        self.assertNotIn("password=secret", serialized)
        self.assertEqual(result["findings"][0]["evidence"]["start_line"], 4)

    def test_nuclei_drops_request_response_curl_and_extracted_values(self):
        raw = json.dumps(
            {
                "template-id": "tech-detect",
                "template-url": "https://templates.invalid/tech",
                "info": {"name": "Technology detection", "severity": "info"},
                "matched-at": "https://example.test/admin?token=secret",
                "matcher-name": "wordpress",
                "type": "http",
                "request": "GET /admin",
                "response": "secret-body",
                "curl-command": "curl -H Authorization:secret",
                "extracted-results": ["secret-value"],
            }
        )
        result = parse_nuclei_jsonl(raw + "\n", version="3.4.0", asset_key=ASSET)
        finding = result["findings"][0]
        serialized = json.dumps(finding)
        for secret in (
            "secret-body",
            "Authorization:secret",
            "secret-value",
            "token=secret",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(finding["evidence"]["path"], "/admin")
        self.assertEqual(result["status"], "partial")

    def test_nuclei_truncated_line_fails_closed(self):
        raw = (
            json.dumps({"template-id": "a", "info": {"name": "A", "severity": "low"}})
            + '\n{"template-id":'
        )
        with self.assertRaisesRegex(ValueError, "truncated"):
            parse_nuclei_jsonl(raw, version="3", asset_key=ASSET)

    def test_nuclei_empty_stream_does_not_claim_coverage(self):
        result = parse_nuclei_jsonl("", version="3", asset_key=ASSET)
        self.assertEqual(result["status"], "completed")
        self.assertIsNone(result["coverage"]["objects_tested"])
        self.assertEqual(result["findings"], [])

    def test_semgrep_requires_login_fingerprint_uses_occurrence_location(self):
        """Use location identity when Semgrep provides no usable fingerprint."""
        raw = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule",
                        "path": "a.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 2},
                        "extra": {
                            "message": "A",
                            "severity": "WARNING",
                            "fingerprint": "requires login",
                        },
                    },
                    {
                        "check_id": "rule",
                        "path": "b.py",
                        "start": {"line": 1, "col": 1},
                        "end": {"line": 1, "col": 2},
                        "extra": {
                            "message": "B",
                            "severity": "WARNING",
                            "fingerprint": "requires login",
                        },
                    },
                ],
                "paths": {"scanned": ["a.py", "b.py"]},
                "errors": [],
            }
        )
        result = parse_semgrep_json(raw, version="1", asset_key=ASSET)
        ids = [finding["external_id"] for finding in result["findings"]]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)
        self.assertNotIn("requires login", ids)

    def test_trivy_same_vulnerability_in_two_targets_has_distinct_identity(self):
        """Keep identical Trivy findings distinct across scanner targets."""
        vulnerability = {
            "VulnerabilityID": "CVE-TEST",
            "PkgName": "demo",
            "InstalledVersion": "1.0",
            "Severity": "HIGH",
        }
        raw = json.dumps(
            {
                "Results": [
                    {
                        "Target": "a.lock",
                        "Class": "lang-pkgs",
                        "Type": "pip",
                        "Vulnerabilities": [vulnerability],
                    },
                    {
                        "Target": "b.lock",
                        "Class": "lang-pkgs",
                        "Type": "pip",
                        "Vulnerabilities": [vulnerability],
                    },
                ]
            }
        )
        result = parse_trivy_json(raw, version="1", asset_key=ASSET)
        ids = [finding["external_id"] for finding in result["findings"]]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)

    def test_nuclei_same_template_on_two_paths_has_distinct_identity(self):
        """Keep Nuclei occurrences distinct across matched paths."""
        base = {
            "template-id": "tech-detect",
            "template-url": "https://templates.invalid/tech",
            "info": {"name": "Technology detection", "severity": "info"},
            "matcher-name": "wordpress",
            "type": "http",
        }
        raw = "\n".join(
            json.dumps({**base, "matched-at": matched})
            for matched in ("https://example.test/a", "https://example.test/b")
        )
        result = parse_nuclei_jsonl(raw + "\n", version="3", asset_key=ASSET)
        ids = [finding["external_id"] for finding in result["findings"]]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)

    def test_output_limit_and_utf8_enforced(self):
        with self.assertRaisesRegex(ValueError, "too large"):
            parse_scanner_output(
                "semgrep-json",
                "x" * (MAX_OUTPUT_BYTES + 1),
                version="1",
                asset_key=ASSET,
            )
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            parse_scanner_output("trivy-json", b"\xff", version="1", asset_key=ASSET)

    def test_unknown_adapter_and_bad_version_rejected(self):
        with self.assertRaises(ValueError):
            parse_scanner_output("unknown", "{}", version="1", asset_key=ASSET)
        with self.assertRaises(ValueError):
            parse_scanner_output("trivy-json", "{}", version="", asset_key=ASSET)

    def test_fingerprint_is_stable_for_same_semantic_finding(self):
        raw = json.dumps(
            {
                "results": [
                    {
                        "check_id": "x.rule",
                        "path": "a.py",
                        "start": {"line": 1},
                        "end": {"line": 1},
                        "extra": {
                            "message": "x",
                            "severity": "INFO",
                            "fingerprint": "stable",
                        },
                    }
                ],
                "errors": [],
            }
        )
        one = parse_semgrep_json(raw, version="1", asset_key=ASSET)["findings"][0]
        two = parse_semgrep_json(raw, version="1", asset_key=ASSET)["findings"][0]
        self.assertEqual(one["fingerprint"], two["fingerprint"])


if __name__ == "__main__":
    unittest.main()
