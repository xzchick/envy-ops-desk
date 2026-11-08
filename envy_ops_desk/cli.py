"""Command-line entry point. The Ops Desk window is the default.

Every write goes to a brand-new file; Ops Desk never overwrites a source.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import __version__
from .core import (OpsDeskError, append, check_passphrase, create, export,
                   handoff_create, handoff_import, handoff_inspect, inspect,
                   state_from, template, write_ical)


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="envy-ops-desk",
        description="Offline, encrypted, revision-preserving operations plans with authenticated "
                    "handoffs. Run with no arguments to open the Ops Desk window. Local only: no "
                    "network, no accounts, no messages, no trusted timestamps.")
    root.add_argument("--version", action="version", version=f"envy-ops-desk {__version__}")
    commands = root.add_subparsers(dest="command")
    commands.add_parser("gui", help="open the Ops Desk window (default)")

    new = commands.add_parser("new", help="create a new encrypted plan")
    new.add_argument("destination", help="a new file for the encrypted plan; never overwritten")
    new.add_argument("--title", required=True, help="the plan title")
    new.add_argument("--objective", default="", help="an optional one-line objective")

    add = commands.add_parser("add", help="append a JSON record and write a new encrypted revision")
    add.add_argument("source", help="the current encrypted plan")
    add.add_argument("destination", help="a new file for the next revision; never overwritten")
    add.add_argument("--record", required=True, help="a JSON file holding one record")

    tmpl = commands.add_parser("template", help="write a blank record template to edit")
    tmpl.add_argument("destination", help="a new JSON file; never overwritten")
    tmpl.add_argument("--kind", default="assignment",
                      choices=("alias", "assignment", "progress", "checkin", "acknowledgement"))

    insp = commands.add_parser("inspect", help="print the decrypted records (read-only)")
    insp.add_argument("source")

    st = commands.add_parser("state", help="print current assignments, check-ins and aliases with due states")
    st.add_argument("source")
    st.add_argument("--pretty", action="store_true", help="print a human-readable table instead of JSON")
    st.add_argument("--no-color", action="store_true", help="disable ANSI colour in --pretty output")

    hc = commands.add_parser("handoff", help="seal the plan into an authenticated handoff bundle")
    hc.add_argument("source", help="the current encrypted plan")
    hc.add_argument("destination", help="a new handoff file; never overwritten")
    hc.add_argument("--note", default="", help="an optional note to the recipient")

    hi = commands.add_parser("import", help="import a handoff bundle into a new encrypted plan")
    hi.add_argument("source", help="the handoff bundle")
    hi.add_argument("destination", help="a new file for the re-encrypted plan; never overwritten")

    hs = commands.add_parser("handoff-inspect", help="print a handoff's summary without importing (read-only)")
    hs.add_argument("source")

    exp = commands.add_parser("export", help="write a plaintext HTML or JSON report")
    exp.add_argument("source")
    exp.add_argument("destination", help="a new report file; never overwritten")
    exp.add_argument("--format", default="html", choices=("html", "json"))

    ic = commands.add_parser("ical", help="write due dates to an iCal (.ics) calendar file")
    ic.add_argument("source")
    ic.add_argument("destination", help="a new .ics file; never overwritten")
    return root


def _passphrase(confirm: bool = False, prompt: str = "Plan passphrase: ") -> bytes:
    if not sys.stdin.isatty():
        raise OpsDeskError("Open this action in a terminal so the passphrase is not echoed")
    value = getpass.getpass(prompt).encode()
    if confirm and value != getpass.getpass("Repeat passphrase: ").encode():
        raise OpsDeskError("Passphrases do not match")
    return check_passphrase(value)


def _run(args) -> int:
    if args.command == "template":
        result = template(args.destination, args.kind)
        print(f"template: wrote {result['output']}")
        print(result["next"])
        return 0
    if args.command == "new":
        result = create(args.destination, args.title, _passphrase(confirm=True), args.objective)
        print(f"new plan: wrote {result['output']} (revision {result['revision']})")
        return 0
    if args.command == "add":
        result = append(args.source, args.destination, args.record, _passphrase())
        print(f"added record {result['added_record_id']} → {result['output']} (revision {result['revision']})")
        return 0
    if args.command == "export":
        result = export(args.source, args.destination, _passphrase(), args.format)
        print(f"export ({result['format']}): wrote {result['output']}  sha256 {result['sha256']}")
        return 0
    if args.command == "handoff":
        plan_secret = _passphrase(prompt="Plan passphrase: ")
        handoff_secret = _passphrase(confirm=True, prompt="Handoff passphrase: ")
        result = handoff_create(args.source, args.destination, plan_secret, handoff_secret, args.note)
        print(f"handoff: wrote {result['output']} (revision {result['revision']})")
        print(result["note"])
        return 0
    if args.command == "import":
        handoff_secret = _passphrase(prompt="Handoff passphrase: ")
        plan_secret = _passphrase(confirm=True, prompt="New plan passphrase: ")
        result = handoff_import(args.source, args.destination, handoff_secret, plan_secret)
        print(f"imported handoff → {result['output']} (revision {result['revision']})")
        print(result["note"])
        return 0
    if args.command == "handoff-inspect":
        print(json.dumps(handoff_inspect(args.source, _passphrase(prompt="Handoff passphrase: ")),
                         indent=2, ensure_ascii=False))
        return 0
    if args.command == "inspect":
        print(json.dumps(inspect(args.source, _passphrase()), indent=2, ensure_ascii=False))
        return 0
    if args.command == "ical":
        result = write_ical(args.source, args.destination, _passphrase())
        print(f"ical: wrote {result['events']} event(s) → {result['output']}  sha256 {result['sha256']}")
        return 0
    if args.command == "state":
        st = state_from(args.source, _passphrase())
        if args.pretty:
            print(_render_state(st, color=sys.stdout.isatty() and not args.no_color))
        else:
            print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0
    return 0


# ANSI colour per due state for the --pretty table.
_STATE_ANSI = {"overdue": "31", "due soon": "33", "scheduled": "36",
               "settled": "32", "no due time": "90"}


def _tint(text, code, color):
    return f"\033[{code}m{text}\033[0m" if color else text


def _render_state(st, color):
    lines = [f"{st['title']}  ·  revision {st['revision']}"]
    if st["assignments"]:
        lines.append("Assignments:")
        for a in st["assignments"]:
            ds = _tint(f"{a['due_state']:>11}", _STATE_ANSI.get(a["due_state"], "0"), color)
            lines.append(f"  [{ds}] {a['task']}  ({a['assignee'] or 'unassigned'}, {a['status']}, "
                         f"due {a['due_utc'] or '—'})")
    if st["checkins"]:
        lines.append("Check-ins:")
        for c in st["checkins"]:
            ds = _tint(f"{c['due_state']:>11}", _STATE_ANSI.get(c["due_state"], "0"), color)
            lines.append(f"  [{ds}] {c['label']}  ({c['assignee'] or 'unassigned'}, due {c['due_utc']})")
    if not st["assignments"] and not st["checkins"]:
        lines.append("  (no assignments or check-ins yet)")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in (None, "gui"):
        from .gui import run_app
        return run_app()
    try:
        return _run(args)
    except OpsDeskError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
