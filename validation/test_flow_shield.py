import unittest
from flow_shield import Action, FlowShield

class FlowShieldTests(unittest.TestCase):
    def test_allowed_read(self):
        f=FlowShield("audit","agent")
        self.assertEqual(f.record(Action("agent","audit","read","record")), "allow")
    def test_reject_unapproved_recipient(self):
        f=FlowShield("audit","agent")
        with self.assertRaises(PermissionError):
            f.record(Action("agent","audit","send","summary",recipient="outside"))
    def test_reject_toxic_composition(self):
        f=FlowShield("audit","agent",frozenset({"approved"}))
        f.record(Action("agent","audit","read","customer",labels=frozenset({"sensitive"})))
        with self.assertRaises(PermissionError):
            f.record(Action("agent","audit","send","summary",recipient="approved"))
    def test_reject_task_drift(self):
        f=FlowShield("audit","agent")
        self.assertFalse(f.check(Action("agent","other","read","record"))[0])
    def test_reject_untrusted_origin(self):
        f=FlowShield("audit","agent")
        self.assertFalse(f.check(Action("agent","audit","read","record",trusted_origin=False))[0])

if __name__ == "__main__":
    unittest.main()
