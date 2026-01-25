import unittest


from app.services.backup import detect_change


class TestDetectChange(unittest.TestCase):
    def test_initial_snapshot_counts_as_changed(self) -> None:
        changed, summary = detect_change(logs=[], new_hash="abc", old_hash=None)
        self.assertTrue(changed)
        self.assertEqual(summary, "Initial snapshot")

    def test_hash_change_counts_as_changed(self) -> None:
        changed, summary = detect_change(logs=[], new_hash="new", old_hash="old")
        self.assertTrue(changed)
        self.assertEqual(summary, "Hash changed")

    def test_logs_without_hash_change_do_not_trigger_backup(self) -> None:
        logs = [{"logged_at": "2026-01-01 00:00:00", "topics": "system,info", "message": "config changed by api"}]
        changed, summary = detect_change(logs=logs, new_hash="same", old_hash="same")
        self.assertFalse(changed)
        self.assertEqual(summary, "No changes detected")


if __name__ == "__main__":
    unittest.main()

