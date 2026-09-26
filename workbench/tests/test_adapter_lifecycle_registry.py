import tempfile
import unittest
from pathlib import Path

from workbench.adapter_lifecycle import AdapterLifecycle
from workbench.engine import Cancelled
from workbench.registry import ExecutionRegistry, RegistryPolicy


class RealRegistryLifecycleTests(unittest.TestCase):
    def test_native_project_receipt_survives_durable_lifecycle_without_persisting_root(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "customer-project"
            root.mkdir()
            (root / ".env").write_text("DO_NOT_READ=this-value", encoding="utf-8")
            (root / "README.md").write_text("safe", encoding="utf-8")
            database = Path(temp) / "state" / "reports.sqlite3"
            registry = ExecutionRegistry(
                RegistryPolicy(
                    max_effect="read_only", allow_filesystem=True, allow_network=False
                )
            )
            lifecycle = AdapterLifecycle(database, registry)
            request = {
                "root": str(root),
                "asset_key": "asset-1",
                "max_files": 20,
                "max_depth": 4,
                "timeout_seconds": 5,
            }

            planned = lifecycle.plan("native-project-metadata", request)
            self.assertEqual(
                planned["request_summary"]["project_label"], "customer-project"
            )
            self.assertFalse(planned["request_summary"]["full_path_included"])
            lifecycle.approve(planned["id"], planned["plan_sha256"])
            completed = lifecycle.execute(
                planned["id"], "native-project-metadata", request
            )

            self.assertEqual(completed["status"], "completed")
            self.assertEqual(
                completed["receipt"]["result"]["verification_authority"],
                "workbench_only",
            )
            self.assertTrue(
                all(
                    item["verification"] == "candidate"
                    for item in completed["receipt"]["result"]["findings"]
                )
            )
            raw = database.read_bytes()
            self.assertNotIn(str(root).encode(), raw)
            self.assertNotIn(b"DO_NOT_READ=this-value", raw)

    def test_native_web_cancelled_reader_persists_cancelled_lifecycle(self):
        """Persist a cancelled terminal lifecycle when the web reader is cancelled."""
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / "state" / "reports.sqlite3"
            lifecycle = AdapterLifecycle(database, ExecutionRegistry())
            request = {
                "target": "https://example.com/",
                "asset_key": "asset-1",
                "timeout_seconds": 5,
            }
            planned = lifecycle.plan("native-web-headers", request)
            lifecycle.approve(planned["id"], planned["plan_sha256"])

            def cancelled_reader(_target):
                """Raise the engine cancellation signal from a synthetic reader."""
                raise Cancelled()

            with self.assertRaises(InterruptedError):
                lifecycle.execute(
                    planned["id"],
                    "native-web-headers",
                    request,
                    web_reader=cancelled_reader,
                )

            stored = lifecycle.get(planned["id"])
            self.assertEqual(stored["status"], "cancelled")
            self.assertEqual(stored["outcome"], {"code": "cancelled"})
            self.assertIsNone(stored["receipt"])


if __name__ == "__main__":
    unittest.main()
