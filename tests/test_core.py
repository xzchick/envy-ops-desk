"""Core Ops Desk tests: encrypted round trips, the journal hash chain, record
kinds, computed due states, authenticated handoffs, export and the no-overwrite
guarantee. Standard library + cryptography.
"""

import datetime
import json
from pathlib import Path
import tempfile
import unittest

from envy_ops_desk import core
from envy_ops_desk.core import OpsDeskError


def utc(text):
    return datetime.datetime.fromisoformat(text)


class OpsDeskTest(unittest.TestCase):
    SECRET = b"a long private ops passphrase"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="envy-ops-"))
        self.addCleanup(__import__("shutil").rmtree, self.dir)

    def new_plan(self, name="r0", title="Plan", objective="Do the thing"):
        path = self.dir / name
        core.create(path, title, self.SECRET, objective)
        return path

    def add(self, src, dst_name, value):
        dst = self.dir / dst_name
        return core.append_record(src, dst, value, self.SECRET), dst

    # ----- envelope -----------------------------------------------------
    def test_encrypted_round_trip_and_magic(self):
        blob = core.encrypt_bytes(b"ops secret", self.SECRET)
        self.assertTrue(blob.startswith(core.MAGIC))
        self.assertEqual(core.decrypt_bytes(blob, self.SECRET), b"ops secret")

    def test_wrong_passphrase_is_a_clean_error(self):
        blob = core.encrypt_bytes(b"x" * 40, self.SECRET)
        with self.assertRaises(OpsDeskError):
            core.decrypt_bytes(blob, b"the wrong passphrase!!")

    def test_short_passphrase_rejected(self):
        with self.assertRaises(OpsDeskError):
            core.create(self.dir / "short", "Plan", b"tooshort")

    def test_vault_envelope_compatible(self):
        # The envelope is byte-identical to ENVY Vault's: MAGIC + 16 salt + 12 nonce + ct.
        blob = core.encrypt_bytes(b"interop", self.SECRET)
        self.assertEqual(blob[:len(core.MAGIC)], b"ENVYVAULT2\x00")

    # ----- create / load ------------------------------------------------
    def test_create_then_load_is_empty_revision_zero(self):
        path = self.new_plan(title="Night shift", objective="Authorized lab visit")
        data, envelope = core._load(path, self.SECRET)
        self.assertEqual(data["revision"], 0)
        self.assertEqual(data["title"], "Night shift")
        self.assertEqual(data["objective"], "Authorized lab visit")
        self.assertEqual(data["records"], [])
        self.assertEqual(len(envelope), 64)

    # ----- append / hash chain -----------------------------------------
    def test_append_chains_and_increments_revision(self):
        p0 = self.new_plan()
        res, p1 = self.add(p0, "r1", {"kind": "alias", "title": "Raven", "role_label": "Lead"})
        self.assertEqual(res["revision"], 1)
        self.assertTrue(res["input_preserved"])
        self.assertTrue(p0.exists(), "the previous revision must be preserved")
        res2, p2 = self.add(p1, "r2", {"kind": "assignment", "title": "Review inventory", "assignee": "Raven"})
        self.assertEqual(res2["revision"], 2)
        data, _ = core._load(p2, self.SECRET)
        self.assertEqual(data["records"][1]["previous_sha256"], data["records"][0]["record_sha256"])

    def test_tampered_record_breaks_the_chain(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "assignment", "title": "Real task"})
        data, _ = core._load(p1, self.SECRET)
        data["records"][0]["title"] = "Forged"  # changed without re-hashing
        forged = self.dir / "forged"
        forged.write_bytes(core.encrypt_bytes(core._canonical(data), self.SECRET))
        with self.assertRaises(OpsDeskError):
            core.inspect(forged, self.SECRET)

    # ----- record validation -------------------------------------------
    def test_assignment_defaults_to_todo(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "assignment", "title": "Task"})
        view = core.state_from(p1, self.SECRET)
        self.assertEqual(view["assignments"][0]["status"], "todo")

    def test_checkin_requires_due_time(self):
        p0 = self.new_plan()
        with self.assertRaises(OpsDeskError):
            self.add(p0, "bad", {"kind": "checkin", "title": "Call"})

    def test_due_time_must_be_utc(self):
        p0 = self.new_plan()
        with self.assertRaises(OpsDeskError):
            self.add(p0, "bad", {"kind": "checkin", "title": "Call", "due_utc": "2026-10-17T16:00:00+02:00"})

    def test_ical_export(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "checkin", "title": "Lab call", "assignee": "Raven",
                                    "due_utc": "2026-10-17T14:00:00+00:00"})
        text = core.ical(p1, self.SECRET).decode("utf-8")
        self.assertIn("BEGIN:VCALENDAR", text)
        self.assertIn("SUMMARY:Lab call (Raven)", text)
        self.assertIn("DTSTART:20261017T140000Z", text)       # UTC, iCal basic format
        self.assertTrue(text.endswith("END:VCALENDAR\r\n"))
        out = self.dir / "cal.ics"
        res = core.write_ical(p1, out, self.SECRET)
        self.assertEqual(res["events"], 1)
        self.assertTrue(out.exists())

    def test_bad_status_rejected(self):
        p0 = self.new_plan()
        with self.assertRaises(OpsDeskError):
            self.add(p0, "bad", {"kind": "assignment", "title": "T", "status": "maybe"})

    def test_progress_must_reference_an_assignment(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "alias", "title": "Raven"})
        with self.assertRaises(OpsDeskError):
            self.add(p1, "bad", {"kind": "progress", "title": "p", "status": "doing",
                                 "references": [self.alias_id(p1)]})

    def alias_id(self, path):
        data, _ = core._load(path, self.SECRET)
        return data["records"][0]["id"]

    def test_role_label_only_on_alias(self):
        p0 = self.new_plan()
        with self.assertRaises(OpsDeskError):
            self.add(p0, "bad", {"kind": "assignment", "title": "T", "role_label": "nope"})

    # ----- derived state: progress + acknowledgement -------------------
    def _plan_with_assignment(self):
        p0 = self.new_plan()
        res, p1 = self.add(p0, "r1", {"kind": "assignment", "title": "Review inventory",
                                      "assignee": "Raven", "due_utc": "2026-10-17T16:00:00+00:00"})
        return p1, res["added_record_id"]

    def test_latest_progress_sets_status_and_note(self):
        p1, aid = self._plan_with_assignment()
        _, p2 = self.add(p1, "r2", {"kind": "progress", "title": "p", "status": "doing",
                                    "note": "Halfway", "references": [aid]})
        _, p3 = self.add(p2, "r3", {"kind": "progress", "title": "p", "status": "blocked",
                                    "note": "Door locked", "references": [aid]})
        view = core.state_from(p3, self.SECRET)
        assignment = view["assignments"][0]
        self.assertEqual(assignment["status"], "blocked")
        self.assertEqual(assignment["progress_note"], "Door locked")

    def test_acknowledgement_settles_due_state(self):
        p1, aid = self._plan_with_assignment()
        # Past due date -> overdue, until acknowledged.
        now = utc("2026-10-20T00:00:00+00:00")
        view = core.state_from(p1, self.SECRET, now=now)
        self.assertEqual(view["assignments"][0]["due_state"], "overdue")
        _, p2 = self.add(p1, "r2", {"kind": "acknowledgement", "title": "Done", "references": [aid]})
        view2 = core.state_from(p2, self.SECRET, now=now)
        self.assertEqual(view2["assignments"][0]["due_state"], "settled")
        self.assertTrue(view2["assignments"][0]["acknowledged"])

    def test_due_states_overdue_soon_scheduled(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "checkin", "title": "soon",
                                    "due_utc": "2026-10-17T10:00:00+00:00"})
        _, p2 = self.add(p1, "r2", {"kind": "checkin", "title": "later",
                                    "due_utc": "2026-10-20T10:00:00+00:00"})
        now = utc("2026-10-17T00:00:00+00:00")  # soon within 24h, later not
        view = core.state_from(p2, self.SECRET, now=now)
        by_label = {c["label"]: c["due_state"] for c in view["checkins"]}
        self.assertEqual(by_label["soon"], "due soon")
        self.assertEqual(by_label["later"], "scheduled")

    def test_state_lists_aliases_assignments_checkins(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "alias", "title": "Raven", "role_label": "Lead"})
        _, p2 = self.add(p1, "r2", {"kind": "assignment", "title": "Task"})
        _, p3 = self.add(p2, "r3", {"kind": "checkin", "title": "Call", "due_utc": "2026-10-17T10:00:00+00:00"})
        view = core.state_from(p3, self.SECRET)
        self.assertEqual(len(view["aliases"]), 1)
        self.assertEqual(len(view["assignments"]), 1)
        self.assertEqual(len(view["checkins"]), 1)
        self.assertEqual(view["aliases"][0]["role_label"], "Lead")

    # ----- handoffs -----------------------------------------------------
    def test_handoff_round_trip_preserves_plan(self):
        p1, aid = self._plan_with_assignment()
        handoff = self.dir / "h.envyho"
        ho_secret = b"a shared handoff secret"
        res = core.handoff_create(p1, handoff, self.SECRET, ho_secret, note="For Raven")
        self.assertTrue(res["authenticated"])
        imported = self.dir / "imported"
        recipient_secret = b"recipients own passphrase"
        core.handoff_import(handoff, imported, ho_secret, recipient_secret)
        original, _ = core._load(p1, self.SECRET)
        copy, _ = core._load(imported, recipient_secret)
        self.assertEqual(original["operation_id"], copy["operation_id"])
        self.assertEqual(original["records"], copy["records"])

    def test_handoff_wrong_passphrase_fails(self):
        p1, _ = self._plan_with_assignment()
        handoff = self.dir / "h.envyho"
        core.handoff_create(p1, handoff, self.SECRET, b"a shared handoff secret")
        with self.assertRaises(OpsDeskError):
            core.handoff_import(handoff, self.dir / "x", b"the wrong secret here", self.SECRET)

    def test_handoff_inspect_reveals_no_identity(self):
        p1, _ = self._plan_with_assignment()
        handoff = self.dir / "h.envyho"
        core.handoff_create(p1, handoff, self.SECRET, b"a shared handoff secret", note="hi")
        info = core.handoff_inspect(handoff, b"a shared handoff secret")
        self.assertEqual(info["note"], "hi")
        self.assertIn("does not establish who", info["warning"])

    def test_plain_plan_is_not_a_handoff(self):
        p0 = self.new_plan()
        with self.assertRaises(OpsDeskError):
            core.handoff_inspect(p0, self.SECRET)

    # ----- export -------------------------------------------------------
    def test_export_html_and_json_are_plaintext_and_safe(self):
        p1, aid = self._plan_with_assignment()
        html_out = self.dir / "report.html"
        res = core.export(p1, html_out, self.SECRET, "html")
        text = html_out.read_text()
        self.assertEqual(res["format"], "html")
        self.assertIn("Content-Security-Policy", text)
        self.assertIn("Review inventory", text)
        json_out = self.dir / "report.json"
        core.export(p1, json_out, self.SECRET, "json")
        report = json.loads(json_out.read_text())
        self.assertEqual(report["plan"]["revision"], 1)
        self.assertIn("limitations", report)

    def test_export_html_escapes_markup(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "alias", "title": "Raven <script>"})
        out = self.dir / "r.html"
        core.export(p1, out, self.SECRET, "html")
        body = out.read_text()
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)

    # ----- no overwrite -------------------------------------------------
    def test_new_file_never_overwrites(self):
        keep = self.dir / "keep"
        keep.write_bytes(b"precious")
        with self.assertRaises(OpsDeskError):
            core.new_file(keep, b"clobber")
        self.assertEqual(keep.read_bytes(), b"precious")

    def test_append_refuses_to_overwrite_destination(self):
        p0 = self.new_plan()
        dest = self.dir / "exists"
        dest.write_bytes(b"keep me")
        with self.assertRaises(OpsDeskError):
            core.append_record(p0, dest, {"kind": "alias", "title": "n"}, self.SECRET)
        self.assertEqual(dest.read_bytes(), b"keep me")

    def test_template_writes_editable_json(self):
        out = self.dir / "tmpl.json"
        core.template(out, "checkin")
        value = json.loads(out.read_text())
        self.assertEqual(value["kind"], "checkin")
        self.assertIn("due_utc", value)

    # ----- state filter by assignee (v0.2) -----------------------------
    def test_state_filter_by_assignee(self):
        p0 = self.new_plan()
        _, p1 = self.add(p0, "r1", {"kind": "assignment", "title": "Review inventory", "assignee": "Raven"})
        _, p2 = self.add(p1, "r2", {"kind": "assignment", "title": "Patch host", "assignee": "Wren"})
        _, p3 = self.add(p2, "r3", {"kind": "checkin", "title": "Lab call", "assignee": "raven",
                                    "due_utc": "2026-10-17T14:00:00+00:00"})
        full = core.state_from(p3, self.SECRET)
        self.assertEqual(len(full["assignments"]), 2)
        raven = core.state_from(p3, self.SECRET, assignee="RAVEN")   # case-insensitive
        self.assertEqual([a["task"] for a in raven["assignments"]], ["Review inventory"])
        self.assertEqual(len(raven["checkins"]), 1)                  # "raven" == "RAVEN"
        self.assertEqual(raven["filtered_assignee"], "RAVEN")
        none = core.state_from(p3, self.SECRET, assignee="nobody")
        self.assertEqual((none["assignments"], none["checkins"]), ([], []))


if __name__ == "__main__":
    unittest.main()
