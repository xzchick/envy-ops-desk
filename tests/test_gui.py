"""Offscreen GUI tests: drive the real ENVY Ops Desk window without a display."""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    import PyQt6.QtWidgets  # noqa: F401
    HAVE_QT = True
except Exception:  # pragma: no cover - PyQt6 missing
    HAVE_QT = False

from envy_ops_desk import core

SECRET = b"a long private ops passphrase"
HANDOFF = b"a separate handoff passphrase"


@unittest.skipUnless(HAVE_QT, "PyQt6 is not installed")
class OpsDeskWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from envy_ops_desk.gui import _build
        app_cls, cls.Window = _build()
        cls.app = app_cls.instance() or app_cls([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        plan = self.root / "plan.envyops"
        core.create(plan, "Exercise", SECRET, "Run the tabletop")
        # Two aliases: "Kestrel" stands for the role "Lead"; work is addressed to either name.
        p = plan
        for n, value in enumerate([
                {"kind": "alias", "title": "Kestrel", "role_label": "Lead"},
                {"kind": "alias", "title": "Wren", "role_label": "Comms"},
                {"kind": "assignment", "title": "Brief the team", "assignee": "Kestrel"},
                {"kind": "assignment", "title": "Book the room", "assignee": "Lead"},
                {"kind": "assignment", "title": "Draft the notice", "assignee": "Wren"}], 1):
            nxt = self.root / f"plan.r{n}.envyops"
            core.append_record(p, nxt, value, SECRET)
            p = nxt
        self.plan = p
        self.w = self.Window()
        self.warnings = []
        self.w._warn = lambda message, icon=None, title="Ops Desk": self.warnings.append(message)
        self.w._open_path(p, SECRET)

    def tearDown(self):
        self.w.timer.stop()
        self.w.close()
        self.tmp.cleanup()

    def cells(self, table, col):
        return [table.item(r, col).text() for r in range(table.rowCount()) if table.item(r, col)]

    def test_my_items_matches_the_alias_and_its_role(self):
        self.assertEqual(self.w.t_assign.rowCount(), 3)
        self.w.f_mine.setCurrentIndex(self.w.f_mine.findData("Kestrel"))
        self.assertEqual(sorted(self.cells(self.w.t_assign, 0)), ["Book the room", "Brief the team"])
        self.assertIn("2 of 3 assignments", self.w.f_note.text())
        self.assertIn("for Kestrel or the Lead role", self.w.f_note.text())
        self.w.f_mine.setCurrentIndex(0)
        self.assertEqual(self.w.t_assign.rowCount(), 3)

    def test_due_filter(self):
        self.w.f_due.setCurrentIndex(self.w.f_due.findData("none"))
        self.assertEqual(self.w.t_assign.rowCount(), 3)          # none of them has a due time
        self.w.f_due.setCurrentIndex(self.w.f_due.findData("overdue"))
        self.assertEqual(self.w.t_assign.rowCount(), 0)

    def test_recurring_checkins_in_one_revision(self):
        before = self.w.data["revision"]
        self.assertTrue(self.w.schedule_recurring("Weekly sync", "2030-01-06T15:00:00+00:00", 7, 4, "Wren"))
        self.assertEqual(self.w.data["revision"], before + 4)
        self.assertEqual(self.cells(self.w.t_check, 2), ["2030-01-06T15:00:00+00:00", "2030-01-13T15:00:00+00:00",
                                                          "2030-01-20T15:00:00+00:00", "2030-01-27T15:00:00+00:00"])
        self.assertIn("Scheduled 4 check-ins every 7 days", self.w.c_status_msg.text())
        self.assertFalse(self.w.schedule_recurring("", "2030-01-06T15:00:00+00:00", 7, 2))

    def test_form_uses_repeat_fields(self):
        self.w.c_label.setText("Stand-up"); self.w.c_due.setText("2030-02-01 09:00")
        self.w.c_every.setValue(1); self.w.c_times.setValue(3)
        self.w.add_checkin()
        self.assertEqual(self.w.t_check.rowCount(), 3)
        self.assertEqual(self.w.c_times.value(), 1)               # reset for the next entry

    def test_verify_handoff_without_importing(self):
        bundle = self.root / "out.envyho"
        core.handoff_create(self.plan, bundle, SECRET, HANDOFF, "for the night shift")
        result = self.w.verify_handoff_file(str(bundle), HANDOFF)
        self.assertTrue(result["valid"])
        self.assertEqual(result["records"], 5)
        self.assertEqual(self.w.source, self.plan)                 # nothing was imported
        self.assertIsNone(self.w.verify_handoff_file(str(bundle), b"the wrong handoff passphrase"))
        self.assertIn("did not verify", self.warnings[-1])


if __name__ == "__main__":
    unittest.main()
