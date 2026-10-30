"""Unit tests for Signing Firewall. No network required (Watchtower uses a fake RPC).

Run: python3 -m unittest tests.test_engine -v
Run from the repo root, or: python3 tests/test_engine.py
"""
import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MAIN = os.path.join(HERE, "..", "signing-firewall.py")
spec = importlib.util.spec_from_file_location("signing_firewall", MAIN)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fresh_state(**overrides):
    cfg = dict(mod.DEFAULT_CONFIG)
    cfg.update(overrides)
    return mod.State(cfg, data_dir=None)


class TestPolicy(unittest.TestCase):
    def test_allowlist_blocks(self):
        st = fresh_state()
        tr, err = mod.propose_transfer(st, "ops-001", "attacker-999", 100)
        self.assertIsNone(tr)
        self.assertIn("allowlisted", err)

    def test_small_transfer_one_approval(self):
        st = fresh_state()
        tr, _ = mod.propose_transfer(st, "ops-001", "vendor-001", 5000)
        tr2, msg = mod.approve_transfer(st, tr["id"], "alice")
        self.assertEqual(tr2["status"], "APPROVED")

    def test_large_transfer_needs_two_approvals(self):
        st = fresh_state()
        tr, _ = mod.propose_transfer(st, "ops-001", "vendor-001", 20000)
        tr2, _ = mod.approve_transfer(st, tr["id"], "alice")
        self.assertEqual(tr2["status"], "PENDING")
        tr3, _ = mod.approve_transfer(st, tr["id"], "bob")
        self.assertEqual(tr3["status"], "APPROVED")

    def test_same_approver_twice_does_not_count(self):
        st = fresh_state()
        tr, _ = mod.propose_transfer(st, "ops-001", "vendor-001", 20000)
        mod.approve_transfer(st, tr["id"], "alice")
        tr2, err = mod.approve_transfer(st, tr["id"], "alice")
        self.assertIsNone(tr2)
        self.assertIn("already approved", err)
        self.assertEqual(st.transfers[tr["id"]]["status"], "PENDING")

    def test_velocity_breach_freezes(self):
        st = fresh_state(velocity_limit=10000, velocity_window_seconds=600)
        for amt in (6000, 6000):
            tr, _ = mod.propose_transfer(st, "ops-001", "vendor-001", amt)
            mod.approve_transfer(st, tr["id"], "alice")
        self.assertTrue(st.frozen)
        tr3, err = mod.propose_transfer(st, "ops-001", "vendor-001", 100)
        self.assertIsNone(tr3)
        self.assertIn("frozen", err)

    def test_timelock_waits_then_releases(self):
        st = fresh_state(timelock_threshold=1000, timelock_seconds=3600,
                         dual_approval_threshold=10000)
        tr, _ = mod.propose_transfer(st, "ops-001", "vendor-001", 5000)
        self.assertTrue(tr["timelock_until"])
        tr2, _ = mod.approve_transfer(st, tr["id"], "alice")
        self.assertEqual(tr2["status"], "WAITING_TIMELOCK")
        # Fake the clock by clearing the timelock, then release must succeed.
        tr["timelock_until"] = "2000-01-01T00:00:00Z"
        tr3, _ = mod.release_transfer(st, tr["id"])
        self.assertEqual(tr3["status"], "APPROVED")


class TestWatchtower(unittest.TestCase):
    def test_parse_delegation(self):
        self.assertEqual(mod.parse_delegation("0x"), "")
        self.assertEqual(mod.parse_delegation(""), "")
        addr = "0x" + "ab" * 20
        self.assertEqual(mod.parse_delegation("0xef0100" + "ab" * 20), addr)
        self.assertEqual(mod.parse_delegation("0x1234"), "OTHER_CODE")

    def test_unauthorised_delegation_freezes(self):
        st = fresh_state()
        evil = "0x" + "ff" * 20
        st.watch["0x" + "11" * 20] = {"address": "0x" + "11" * 20}
        results = mod.check_watchtower(
            st, rpc_func=lambda a: "0xef0100" + "ff" * 20)
        self.assertEqual(results[0]["status"], "ALERT_UNAUTHORISED_DELEGATION")
        self.assertTrue(st.frozen)

    def test_allowlisted_delegation_is_ok(self):
        evil = "0x" + "ff" * 20
        st = fresh_state(allowed_delegations=[evil])
        st.watch["0x" + "11" * 20] = {"address": "0x" + "11" * 20}
        results = mod.check_watchtower(
            st, rpc_func=lambda a: "0xef0100" + "ff" * 20)
        self.assertEqual(results[0]["status"], "OK")
        self.assertFalse(st.frozen)

    def test_rpc_error_does_not_freeze(self):
        st = fresh_state()
        st.watch["0x" + "11" * 20] = {"address": "0x" + "11" * 20}
        def boom(a):
            raise RuntimeError("network down")
        results = mod.check_watchtower(st, rpc_func=boom)
        self.assertEqual(results[0]["status"], "ERROR")
        self.assertFalse(st.frozen)


class TestAudit(unittest.TestCase):
    def test_chain_verifies_and_tamper_breaks(self):
        st = fresh_state()
        mod.propose_transfer(st, "ops-001", "vendor-001", 100)
        self.assertTrue(mod.verify_audit_chain(st.audit))
        st.audit[0]["detail"] = {"tampered": True}
        self.assertFalse(mod.verify_audit_chain(st.audit))


if __name__ == "__main__":
    unittest.main()
