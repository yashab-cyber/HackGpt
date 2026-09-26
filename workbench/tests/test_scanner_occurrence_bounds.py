"""Offline regressions for lossless, bounded scanner occurrence identifiers."""

import json
import unittest

from workbench.adapters import parse_semgrep_json, parse_trivy_json, parse_nuclei_jsonl


class OccurrenceBoundsTests(unittest.TestCase):
    """Long metadata must not make distinct observations reject an entire import."""

    def assert_distinct(self, result):
        """Require two bounded identities and deterministic candidate records."""
        ids = [finding["external_id"] for finding in result["findings"]]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(0 < len(value) <= 200 for value in ids))

    def test_semgrep_long_paths_and_columns(self):
        """Retain location distinctions beyond both output truncation boundaries."""
        for paths, columns in [
            (["x" * 1100 + "/a.py", "x" * 1100 + "/b.py"], [1, 1]),
            (["x" * 300 + "/a.py"] * 2, [1, 2]),
        ]:
            with self.subTest(paths=paths, columns=columns):
                items = [
                    {
                        "check_id": "rule",
                        "path": path,
                        "start": {"line": 1, "col": col},
                        "end": {"line": 1, "col": col + 1},
                        "extra": {"fingerprint": "requires login"},
                    }
                    for path, col in zip(paths, columns)
                ]
                self.assert_distinct(
                    parse_semgrep_json(
                        json.dumps({"results": items}), version="1", asset_key="fixture"
                    )
                )

    def test_semgrep_long_vendor_fingerprints(self):
        """Vendor fingerprints differing beyond character 200 stay distinct."""
        items = [
            {
                "check_id": "rule",
                "path": "a.py",
                "extra": {"fingerprint": "f" * 300 + suffix},
            }
            for suffix in ("a", "b")
        ]
        self.assert_distinct(
            parse_semgrep_json(
                json.dumps({"results": items}), version="1", asset_key="fixture"
            )
        )

    def test_trivy_long_targets(self):
        """Hash full targets before their evidence display is truncated."""
        vuln = {
            "VulnerabilityID": "CVE-fixture",
            "PkgName": "demo",
            "InstalledVersion": "1",
        }
        results = [
            {"Target": "x" * 1100 + suffix, "Vulnerabilities": [vuln]}
            for suffix in ("a", "b")
        ]
        self.assert_distinct(
            parse_trivy_json(
                json.dumps({"Results": results}), version="1", asset_key="fixture"
            )
        )

    def test_trivy_misconfiguration_and_secret_occurrences(self):
        """Apply bounded identity to all Trivy categories without keeping secrets."""
        for category in ("Misconfigurations", "Secrets"):
            with self.subTest(category=category):
                items = []
                for line in (1, 2):
                    item = {
                        "ID": "rule",
                        "RuleID": "rule",
                        "StartLine": line,
                        "EndLine": line,
                        "CauseMetadata": {"StartLine": line, "EndLine": line},
                        "Match": "synthetic-value-not-for-retention",
                    }
                    items.append(item)
                result = parse_trivy_json(
                    json.dumps({"Results": [{"Target": "x" * 300, category: items}]}),
                    version="1",
                    asset_key="fixture",
                )
                self.assert_distinct(result)
                self.assertNotIn(
                    "synthetic-value-not-for-retention", json.dumps(result)
                )

    def test_nuclei_long_paths_templates_and_matchers(self):
        """Exclude query credentials while retaining the complete matched path."""
        base = {
            "template-id": "t" * 180,
            "matcher-name": "m" * 220,
            "info": {"name": "Fixture", "severity": "info"},
        }
        items = [
            {
                **base,
                "matched-at": "https://example.invalid/"
                + "x" * 1100
                + suffix
                + "?token=synthetic-private-value#private-fragment",
            }
            for suffix in ("a", "b")
        ]
        result = parse_nuclei_jsonl(
            "\n".join(json.dumps(item) for item in items),
            version="1",
            asset_key="fixture",
        )
        self.assert_distinct(result)
        self.assertNotIn("synthetic-private-value", json.dumps(result))
        self.assertNotIn("private-fragment", json.dumps(result))

    def test_identical_imports_have_identical_ids(self):
        """Repeated parsing is stable and exact duplicate input still fails closed."""
        item = {
            "check_id": "rule",
            "path": "x" * 300 + "/a.py",
            "start": {"line": 1, "col": 1},
            "extra": {"fingerprint": "requires login"},
        }
        raw = json.dumps({"results": [item]})
        first = parse_semgrep_json(raw, version="1", asset_key="fixture")
        second = parse_semgrep_json(raw, version="1", asset_key="fixture")
        self.assertEqual(first["findings"], second["findings"])
        with self.assertRaisesRegex(ValueError, "duplicate identity"):
            parse_semgrep_json(
                json.dumps({"results": [item, item]}), version="1", asset_key="fixture"
            )


if __name__ == "__main__":
    unittest.main()
