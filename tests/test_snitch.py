import json
import tempfile
import unittest
from pathlib import Path

from snitch.core import Guard, Store, Verdict

CONFIG = {"agents": {"a": "A", "b": "B"}, "mission": "Read public data", "tools": {
    "read": {"agents": ["a", "b"], "risk": "low"},
    "write": {"agents": ["a"], "risk": "high"},
    "think": {"agents": ["a"], "risk": "medium"}}}


class FakeReviewer:
    def review(self, proposal, history, policy):
        return Verdict("block", "Drift detected", "ai_reviewer")


class SnitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(str(Path(self.tmp.name) / "test.db"))
        self.guard = Guard(CONFIG, self.store)

    def tearDown(self):
        self.tmp.cleanup()

    def test_allow_and_execute_then_award_once(self):
        result = self.guard.check("a", {"tool": "read", "arguments": {"q": "weather"}}, True, lambda: (200, "ok"))
        self.assertEqual(result["decision"], "allow")
        executed = self.store.db.execute("SELECT id FROM events WHERE kind='executed'").fetchone()[0]
        self.store.award_completion("a", executed)
        self.assertEqual(self.store.leaderboard()[0]["points"], 2)
        with self.assertRaises(ValueError):
            self.store.award_completion("a", executed)
        self.assertTrue(self.store.verify()["valid"])

    def test_block_quarantine_and_operator_release(self):
        result = self.guard.check("a", {"tool": "read", "arguments": {"cmd": "rm -rf /data"}})
        self.assertEqual(result["decision"], "block")
        self.assertTrue(self.store.held("a"))
        self.assertEqual(self.guard.check("a", {"tool": "read", "arguments": {}})["source"], "kill_switch")
        self.store.release("a")
        self.assertEqual(self.guard.check("a", {"tool": "read", "arguments": {}})["decision"], "allow")

    def test_high_risk_review_and_missing_reviewer(self):
        self.assertEqual(self.guard.check("a", {"tool": "write", "arguments": {}})["decision"], "review")
        self.assertEqual(self.guard.check("a", {"tool": "think", "arguments": {}})["decision"], "review")

    def test_reviewer_blocks_and_does_not_override_rules(self):
        self.guard.reviewer = FakeReviewer()
        self.assertEqual(self.guard.check("a", {"tool": "think", "arguments": {}})["decision"], "block")
        self.store.release("a")
        result = self.guard.check("a", {"tool": "read", "arguments": {"key": "sk-" + "a"*25}})
        self.assertEqual(result["source"], "secret")
        self.assertNotIn("sk-", json.dumps(self.store.recent("a")))

    def test_report_scored_only_after_verification(self):
        event = self.guard.check("a", {"tool": "read", "arguments": {}})["event_id"]
        report = self.store.report("b", "a", event, "Out of scope")
        self.assertEqual(self.store.leaderboard(), [])
        with self.assertRaises(ValueError):
            self.store.report("b", "a", event, "Spam")
        self.store.resolve_report(report, True)
        self.assertEqual(self.store.leaderboard()[0]["points"], 10)
        with self.assertRaises(ValueError):
            self.store.resolve_report(report, True)

    def test_audit_detects_change(self):
        self.guard.check("a", {"tool": "read", "arguments": {}})
        self.store.db.execute("UPDATE events SET data='{}' WHERE id=1")
        self.assertFalse(self.store.verify()["valid"])


if __name__ == "__main__":
    unittest.main()

class ApprovalTests(unittest.TestCase):
    def test_exact_one_time_approval(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "test.db"))
            guard = Guard(CONFIG, store)
            proposal = {"tool": "write", "arguments": {"text": "hello"}}
            store.approve("a", proposal)
            self.assertEqual(guard.check("a", {"tool": "write", "arguments": {"text": "changed"}})["decision"], "review")
            self.assertEqual(guard.check("a", proposal, True, lambda: (200, "ok"))["decision"], "allow")
            self.assertEqual(guard.check("a", proposal)["decision"], "review")
