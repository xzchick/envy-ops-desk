"""CLI tests that need no display. The passphrase prompt is patched."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from envy_ops_desk import cli


class CLITest(unittest.TestCase):
    SECRET = b"a long private ops passphrase"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="envy-ops-cli-"))
        self.addCleanup(__import__("shutil").rmtree, self.dir)

    def invoke(self, *args, secret=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_passphrase", return_value=secret or self.SECRET):
            code = cli.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("envy-ops-desk", out.getvalue())

    def test_new_add_state_flow(self):
        plan = self.dir / "plan.envyops"
        code, out, _ = self.invoke("new", plan, "--title", "Night shift", "--objective", "Lab visit")
        self.assertEqual(code, 0)
        self.assertTrue(plan.exists())

        record = self.dir / "rec.json"
        record.write_text(json.dumps({"kind": "assignment", "title": "Review inventory", "assignee": "Raven"}))
        r1 = self.dir / "plan.r1.envyops"
        code, out, _ = self.invoke("add", plan, r1, "--record", record)
        self.assertEqual(code, 0)
        self.assertTrue(r1.exists())
        self.assertTrue(plan.exists(), "previous revision preserved")

        code, out, _ = self.invoke("state", r1)
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report["assignments"][0]["task"], "Review inventory")

    def test_export_writes_report(self):
        plan = self.dir / "c.envyops"
        self.invoke("new", plan, "--title", "Plan")
        out_html = self.dir / "r.html"
        code, out, _ = self.invoke("export", plan, out_html, "--format", "html")
        self.assertEqual(code, 0)
        self.assertIn("sha256", out)
        self.assertTrue(out_html.exists())

    def test_handoff_and_import_flow(self):
        plan = self.dir / "p.envyops"
        self.invoke("new", plan, "--title", "Plan")
        handoff = self.dir / "h.envyho"
        # handoff prompts for plan then handoff passphrase; patch returns one value for all prompts.
        code, out, _ = self.invoke("handoff", plan, handoff, "--note", "hi")
        self.assertEqual(code, 0)
        self.assertTrue(handoff.exists())
        imported = self.dir / "imported.envyops"
        code, out, _ = self.invoke("import", handoff, imported)
        self.assertEqual(code, 0)
        self.assertTrue(imported.exists())

    def test_template_command(self):
        dest = self.dir / "t.json"
        code, out, _ = self.invoke("template", dest, "--kind", "progress")
        self.assertEqual(code, 0)
        value = json.loads(dest.read_text())
        self.assertEqual(value["kind"], "progress")

    def test_bad_passphrase_is_error(self):
        plan = self.dir / "c2.envyops"
        self.invoke("new", plan, "--title", "Plan")
        code, _, err = self.invoke("state", plan, secret=b"the wrong passphrase!")
        self.assertEqual(code, 2)
        self.assertIn("passphrase", err.lower())

    def test_unknown_command(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["seance"])


if __name__ == "__main__":
    unittest.main()
