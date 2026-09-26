import copy
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing

from workbench.engine import Assessment, Scope, verify_integrity
from workbench.server import State, Store, durable_for_review


def scope():
    return Scope.parse(
        {
            "target": "https://example.com",
            "mode": "analyst",
            "authorized": True,
            "authorization": "Recovery fixture",
        }
    )


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.directory.cleanup()

    def test_stale_running_checkpoint_recovers_as_interrupted(self):
        store = Store(self.directory.name)
        running = Assessment(scope()).report
        store.save_active(running)
        state = State(self.directory.name)
        self.assertEqual(state.recovered_interruptions, 1)
        recovered = state.store.get(running["id"])
        self.assertEqual(recovered["status"], "interrupted")
        self.assertEqual(recovered["verdict"], "inconclusive")
        self.assertEqual(recovered["events"][-1]["kind"], "interrupted")
        self.assertTrue(recovered["events"][-1]["details"]["recovered_after_restart"])
        self.assertTrue(verify_integrity(recovered))

    def test_unsealed_legacy_checkpoint_is_quarantined_not_discarded(self):
        """Preserve pre-sealing checkpoints as explicitly untrusted evidence."""
        store = Store(self.directory.name)
        running = Assessment(scope()).report
        self.assertNotIn("integrity", running)
        with closing(sqlite3.connect(store.path)) as connection:
            connection.execute(
                "INSERT INTO active_runs VALUES (?, ?, ?)",
                (running["id"], running["started_at"], json.dumps(running)),
            )
            connection.commit()

        state = State(self.directory.name)
        self.assertEqual(state.recovered_interruptions, 1)
        recovered = state.store.get(running["id"])
        self.assertEqual(recovered["status"], "interrupted")
        self.assertEqual(recovered["durability"]["status"], "not_durable")
        self.assertEqual(
            recovered["durability"]["reason"],
            "legacy_checkpoint_missing_integrity",
        )
        self.assertTrue(
            recovered["events"][-1]["details"]["legacy_unsealed_checkpoint"]
        )
        self.assertFalse(durable_for_review(recovered))
        self.assertTrue(verify_integrity(recovered))

    def test_finalize_atomically_retires_matching_checkpoint(self):
        store = Store(self.directory.name)
        report = Assessment(
            scope(),
            remote_reader=lambda _: {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "method": "HEAD",
                "redirect_followed": False,
            },
        ).run()
        running = copy.deepcopy(report)
        running.pop("integrity")
        running["status"] = "running"
        running["verdict"] = "pending"
        running["finished_at"] = None
        store.save_active(running)
        store.finalize(report)
        self.assertEqual(store.get(report["id"]), report)
        self.assertEqual(store.recover_interrupted(), 0)

    def test_invalid_active_snapshot_is_never_promoted(self):
        store = Store(self.directory.name)
        running = Assessment(scope()).report
        store.save_active(running)
        with closing(sqlite3.connect(store.path)) as connection:
            data = json.loads(
                connection.execute(
                    "SELECT content FROM active_runs WHERE id = ?", (running["id"],)
                ).fetchone()[0]
            )
            data.setdefault("events", []).append({"sequence": 1, "sha256": "fake"})
            connection.execute(
                "UPDATE active_runs SET content = ? WHERE id = ?",
                (json.dumps(data), running["id"]),
            )
            connection.commit()
        self.assertEqual(store.recover_interrupted(), 0)
        self.assertIsNone(store.get(running["id"]))
        self.assertEqual(store.recover_interrupted(), 0)

    def test_tampered_running_checkpoint_field_is_never_promoted(self):
        """Reject a sealed running checkpoint whose non-event content changed."""
        store = Store(self.directory.name)
        running = Assessment(scope()).report
        store.save_active(running)
        with closing(sqlite3.connect(store.path)) as connection:
            data = json.loads(
                connection.execute(
                    "SELECT content FROM active_runs WHERE id = ?", (running["id"],)
                ).fetchone()[0]
            )
            data["target"] = "https://tampered.invalid"
            connection.execute(
                "UPDATE active_runs SET content = ? WHERE id = ?",
                (json.dumps(data), running["id"]),
            )
            connection.commit()
        self.assertEqual(store.recover_interrupted(), 0)
        self.assertIsNone(store.get(running["id"]))

    def test_running_only_checkpoint_contract(self):
        store = Store(self.directory.name)
        final = Assessment(
            scope(),
            remote_reader=lambda _: {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "method": "HEAD",
                "redirect_followed": False,
            },
        ).run()
        with self.assertRaises(ValueError):
            store.save_active(final)


if __name__ == "__main__":
    unittest.main()
