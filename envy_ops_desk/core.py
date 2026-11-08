"""Encrypted, revision-preserving local operations planning with authenticated handoffs.

A self-contained engine for the ENVY BLACK VEIL Ops Desk, packaged as a standalone
app. Everything is local and offline: a plan holds role aliases, task assignments,
progress updates, scheduled check-ins and acknowledgements in a SHA-256 hash-chained
journal. Every save writes a new encrypted revision; earlier revisions are never
overwritten.

Honest by design: role labels are not access controls, due states are computed from
your own machine clock, and a handoff is an authenticated encrypted bundle that proves
the passphrase — never a sender identity. Plans use the same AES-256-GCM envelope as
ENVY Vault, so files interoperate.

Standard library only, apart from ``cryptography`` for the encrypted envelope.
"""

from __future__ import annotations

import datetime
import hashlib
import html
import json
import os
import stat
import uuid
from pathlib import Path

# --- Shared errors and bounds ------------------------------------------------

MAGIC = b"ENVYVAULT2\x00"
MAX_ENVELOPE = 8 * 1024 * 1024
MAX_RECORD = 128 * 1024
MAX_RECORDS = 1000
MIN_PASSPHRASE = 12
KINDS = ("alias", "assignment", "progress", "checkin", "acknowledgement")
STATUSES = ("todo", "doing", "blocked", "done")
SOON_SECONDS = 24 * 3600


class OpsDeskError(RuntimeError):
    """A clean, expected error: a bad passphrase, an invalid record, a chain mismatch."""


# --- Safe file primitives (never follow symlinks, never overwrite) -----------

def read_regular(path, limit: int = MAX_ENVELOPE) -> bytes:
    path = Path(path).expanduser()
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
            raise OpsDeskError("Expected a regular file within the size limit")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise OpsDeskError("File exceeded the size limit")
    return data


def new_file(path, data: bytes, mode: int = 0o600) -> Path:
    """Write a brand-new file. O_EXCL means an existing file is never overwritten."""
    path = Path(path).expanduser()
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        raise OpsDeskError(f"Refusing to overwrite an existing file: {path}") from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


# --- Encrypted envelope (byte-compatible with ENVY Vault) --------------------

def _key(secret: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(secret)


def encrypt_bytes(data: bytes, secret: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(secret, salt)).encrypt(nonce, data, MAGIC)


def decrypt_bytes(data: bytes, secret: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 44:
        raise OpsDeskError("Not an ENVY encrypted envelope")
    blob = data[len(MAGIC):]
    try:
        return AESGCM(_key(secret, blob[:16])).decrypt(blob[16:28], blob[28:], MAGIC)
    except InvalidTag:
        raise OpsDeskError("Incorrect passphrase or modified encrypted data") from None


def check_passphrase(secret: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_PASSPHRASE:
        raise OpsDeskError(f"Use a passphrase of at least {MIN_PASSPHRASE} bytes")
    return bytes(secret)


# --- Canonical form and field validation -------------------------------------

def _canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _parse_utc(value) -> datetime.datetime:
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise OpsDeskError("Times must be ISO 8601 with a UTC offset") from None
    if parsed.tzinfo is None:
        raise OpsDeskError("Times must include a timezone offset")
    return parsed.astimezone(datetime.timezone.utc)


def _text(value, field, limit, required=True):
    if not isinstance(value, str) or len(value) > limit or "\x00" in value or (required and not value.strip()):
        raise OpsDeskError("Invalid plan record " + field)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise OpsDeskError("Plan record " + field + " must contain valid Unicode text") from None
    return value


def _timestamp(value, field="due_utc"):
    _text(value, field, 64)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise OpsDeskError(field + " must be ISO 8601 with a UTC offset") from None
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise OpsDeskError(field + " must be expressed in UTC (+00:00 or Z)")
    return parsed.isoformat()


def _validate_record(value, previous=()):
    """Validate one content record. ``previous`` maps existing record id -> kind."""
    ids = dict(previous)
    if not isinstance(value, dict) or value.get("kind") not in KINDS:
        raise OpsDeskError("Plan record kind must be one of: " + ", ".join(KINDS))
    kind = value["kind"]
    allowed = {"kind", "title", "assignee", "status", "due_utc", "note", "role_label", "references"}
    if set(value) - allowed:
        raise OpsDeskError("Unknown plan record field")

    record = {"kind": kind, "title": _text(value.get("title"), "title", 200),
              "note": _text(value.get("note", ""), "note", 32000, required=False)}

    # assignee — assignment and check-in may carry one
    if "assignee" in value and value["assignee"] != "":
        if kind not in ("assignment", "checkin"):
            raise OpsDeskError("Only assignments and check-ins take an assignee")
        record["assignee"] = _text(value["assignee"], "assignee", 120)

    # status — assignment and progress
    if "status" in value:
        if kind not in ("assignment", "progress"):
            raise OpsDeskError("Only assignments and progress updates take a status")
        if value["status"] not in STATUSES:
            raise OpsDeskError("Status must be one of: " + ", ".join(STATUSES))
        record["status"] = value["status"]
    elif kind == "assignment":
        record["status"] = "todo"
    elif kind == "progress":
        raise OpsDeskError("A progress update needs a status")

    # due_utc — assignment (optional) and check-in (required)
    if "due_utc" in value and value["due_utc"] != "":
        if kind not in ("assignment", "checkin"):
            raise OpsDeskError("Only assignments and check-ins take a due time")
        record["due_utc"] = _timestamp(value["due_utc"])
    elif kind == "checkin":
        raise OpsDeskError("A check-in needs its due time in UTC")

    # role_label — alias only
    if "role_label" in value and value["role_label"] != "":
        if kind != "alias":
            raise OpsDeskError("Only aliases take a role label")
        record["role_label"] = _text(value["role_label"], "role label", 120)

    # references — progress targets one assignment; acknowledgement targets one record
    refs = value.get("references", [])
    if not isinstance(refs, list) or any(not isinstance(x, str) for x in refs):
        raise OpsDeskError("References must be a list of record IDs")
    if len(set(refs)) != len(refs):
        raise OpsDeskError("Duplicate plan record reference")
    for ref in refs:
        if ref not in ids:
            raise OpsDeskError("A reference must name an existing record in this plan")
    if kind == "progress":
        if len(refs) != 1 or ids.get(refs[0]) != "assignment":
            raise OpsDeskError("A progress update must reference exactly one assignment")
    elif kind == "acknowledgement":
        if len(refs) != 1:
            raise OpsDeskError("An acknowledgement must reference exactly one record")
    elif refs:
        raise OpsDeskError("Only progress updates and acknowledgements take references")
    record["references"] = refs
    return record


def _validate_plan(data):
    fields = {"schema", "operation_id", "title", "objective", "created_utc",
              "revision", "previous_envelope_sha256", "records"}
    if not isinstance(data, dict) or set(data) != fields or type(data["schema"]) is not int or data["schema"] != 1:
        raise OpsDeskError("Unsupported encrypted plan schema")
    _text(data["title"], "plan title", 200)
    _text(data["objective"], "objective", 4000, required=False)
    try:
        uuid.UUID(data["operation_id"])
    except (ValueError, TypeError, AttributeError):
        raise OpsDeskError("Invalid operation identifier") from None
    _timestamp(data["created_utc"], "created_utc")
    records = data["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS or type(data["revision"]) is not int or data["revision"] != len(records):
        raise OpsDeskError("Invalid plan revision or record count")
    if not isinstance(data["previous_envelope_sha256"], str) or len(data["previous_envelope_sha256"]) != 64 \
            or any(c not in "0123456789abcdef" for c in data["previous_envelope_sha256"]):
        raise OpsDeskError("Invalid previous encrypted revision digest")
    previous, seen = "0" * 64, {}
    for record in records:
        meta = {"id", "recorded_utc", "previous_sha256", "record_sha256"}
        if not isinstance(record, dict) or not meta <= set(record):
            raise OpsDeskError("Invalid journal metadata")
        try:
            uuid.UUID(record["id"])
        except (ValueError, TypeError, AttributeError):
            raise OpsDeskError("Invalid record identifier") from None
        if record["id"] in seen:
            raise OpsDeskError("Duplicate record identifier")
        _timestamp(record["recorded_utc"], "recorded_utc")
        content = {k: v for k, v in record.items() if k not in meta}
        normalized = _validate_record(content, seen)
        if normalized != content:
            raise OpsDeskError("Encrypted plan record is incomplete or not normalized")
        core = {k: v for k, v in record.items() if k != "record_sha256"}
        if record["previous_sha256"] != previous or hashlib.sha256(_canonical(core)).hexdigest() != record["record_sha256"]:
            raise OpsDeskError("Plan journal hash chain mismatch")
        previous = record["record_sha256"]
        seen[record["id"]] = record["kind"]
    return data


# --- Load / write encrypted revisions ---------------------------------------

def _load(source, secret):
    encrypted = read_regular(source, MAX_ENVELOPE)
    try:
        data = json.loads(decrypt_bytes(encrypted, secret))
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise OpsDeskError("Encrypted plan does not contain valid JSON") from None
    return _validate_plan(data), hashlib.sha256(encrypted).hexdigest()


def _write(destination, data, secret):
    check_passphrase(secret)
    encoded = _canonical(_validate_plan(data))
    if len(encoded) + 128 > MAX_ENVELOPE:
        raise OpsDeskError("Plan exceeds the 8 MiB encrypted revision limit")
    new_file(destination, encrypt_bytes(encoded, secret))
    return {"output": str(destination), "operation_id": data["operation_id"], "revision": data["revision"],
            "records": len(data["records"]), "encrypted": True, "previous_revision_preserved": True}


def create(destination, title, secret, objective=""):
    return _write(destination, {"schema": 1, "operation_id": str(uuid.uuid4()),
                  "title": _text(title, "plan title", 200),
                  "objective": _text(objective, "objective", 4000, required=False),
                  "created_utc": _utc(), "revision": 0,
                  "previous_envelope_sha256": "0" * 64, "records": []}, secret)


def template(destination, kind="assignment"):
    if kind not in KINDS:
        raise OpsDeskError("Unknown plan record kind")
    examples = {
        "alias": {"kind": "alias", "title": "Raven", "role_label": "Field lead", "note": ""},
        "assignment": {"kind": "assignment", "title": "Review inventory", "assignee": "Raven",
                       "status": "todo", "due_utc": _utc(), "note": "Acknowledge return locally."},
        "progress": {"kind": "progress", "title": "Progress update", "status": "doing",
                     "note": "Halfway through the shelf.", "references": ["REPLACE-WITH-ASSIGNMENT-ID"]},
        "checkin": {"kind": "checkin", "title": "Status call", "assignee": "Raven",
                    "due_utc": _utc(), "note": "Confirm handover window."},
        "acknowledgement": {"kind": "acknowledgement", "title": "Return acknowledged",
                            "note": "Inventory returned.", "references": ["REPLACE-WITH-RECORD-ID"]},
    }
    new_file(destination, (json.dumps(examples[kind], indent=2) + "\n").encode("utf-8"))
    return {"output": str(destination), "plaintext": True,
            "next": "Edit the template locally, add it into a new encrypted revision, then handle the "
                    "plaintext working file according to your storage policy."}


def append(source, destination, record_source, secret):
    try:
        value = json.loads(read_regular(record_source, MAX_RECORD))
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise OpsDeskError("Plan record must contain valid UTF-8 JSON") from None
    return append_record(source, destination, value, secret)


def append_record(source, destination, value, secret):
    """Append a record and write a new encrypted revision, without a plaintext working file."""
    data, previous_envelope = _load(source, secret)
    if len(data["records"]) >= MAX_RECORDS:
        raise OpsDeskError("Plan has reached its 1000 record limit")
    existing = {r["id"]: r["kind"] for r in data["records"]}
    record = _validate_record(value, existing)
    record.update(id=str(uuid.uuid4()), recorded_utc=_utc(),
                  previous_sha256=data["records"][-1]["record_sha256"] if data["records"] else "0" * 64)
    record["record_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    data["records"].append(record)
    data["revision"] += 1
    data["previous_envelope_sha256"] = previous_envelope
    result = _write(destination, data, secret)
    return dict(result, added_record_id=record["id"], input_preserved=True)


def recurring_checkins(source, destination, secret, label, first_due_utc, interval_days, count,
                       assignee="", note=""):
    """Add a series of check-ins at a fixed cadence in one revision: `count` check-ins
    due at first_due_utc, then every `interval_days` after. Each is an ordinary
    check-in record, chained into the journal; they are reminders, not enforcement."""
    if type(count) is not int or isinstance(count, bool) or not 1 <= count <= 200:
        raise OpsDeskError("count must be a whole number from 1 to 200")
    if type(interval_days) is not int or isinstance(interval_days, bool) or not 1 <= interval_days <= 3650:
        raise OpsDeskError("interval_days must be a whole number from 1 to 3650")
    first = _parse_utc(first_due_utc)
    data, previous_envelope = _load(source, secret)
    if len(data["records"]) + count > MAX_RECORDS:
        raise OpsDeskError("Plan would exceed its 1000 record limit")
    ids = []
    for k in range(count):
        due = (first + datetime.timedelta(days=interval_days * k)).isoformat()
        value = {"kind": "checkin", "title": label, "due_utc": due}
        if assignee:
            value["assignee"] = assignee
        if note:
            value["note"] = note
        existing = {r["id"]: r["kind"] for r in data["records"]}
        record = _validate_record(value, existing)
        record.update(id=str(uuid.uuid4()), recorded_utc=_utc(),
                      previous_sha256=data["records"][-1]["record_sha256"] if data["records"] else "0" * 64)
        record["record_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
        data["records"].append(record)
        data["revision"] += 1
        ids.append(record["id"])
    data["previous_envelope_sha256"] = previous_envelope
    result = _write(destination, data, secret)
    return dict(result, checkins=count, first_due_utc=first.isoformat(), added_record_ids=ids)


# --- Derived views: due states, assignments, check-ins, aliases --------------

def _due_state(due_iso, now, settled):
    if settled:
        return "settled"
    due = _parse_utc(due_iso)
    delta = (due - now).total_seconds()
    if delta < 0:
        return "overdue"
    if delta <= SOON_SECONDS:
        return "due soon"
    return "scheduled"


def state(data, now=None):
    """Fold the append-only journal into the current assignments, check-ins and aliases.

    Nothing is inferred: the latest *progress* record for an assignment sets its status
    and progress note, an *acknowledgement* settles the record it references, and due
    states come only from the ``due_utc`` you entered, compared with ``now``.
    """
    _validate_plan(data)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    acknowledged = set()
    latest_progress = {}
    for record in data["records"]:
        if record["kind"] == "acknowledgement" and record["references"]:
            acknowledged.add(record["references"][0])
        elif record["kind"] == "progress" and record["references"]:
            latest_progress[record["references"][0]] = record

    aliases, assignments, checkins = [], [], []
    for record in data["records"]:
        if record["kind"] == "alias":
            aliases.append({"id": record["id"], "alias": record["title"],
                            "role_label": record.get("role_label", ""), "note": record.get("note", "")})
        elif record["kind"] == "assignment":
            progress = latest_progress.get(record["id"])
            status = progress["status"] if progress else record.get("status", "todo")
            note = (progress or record).get("note", "")
            settled = status == "done" or record["id"] in acknowledged
            due = record.get("due_utc")
            assignments.append({"id": record["id"], "task": record["title"],
                                "assignee": record.get("assignee", ""), "status": status,
                                "due_utc": due or "", "progress_note": note,
                                "due_state": _due_state(due, now, settled) if due else "no due time",
                                "acknowledged": record["id"] in acknowledged})
        elif record["kind"] == "checkin":
            settled = record["id"] in acknowledged
            checkins.append({"id": record["id"], "label": record["title"],
                             "assignee": record.get("assignee", ""), "due_utc": record["due_utc"],
                             "note": record.get("note", ""),
                             "due_state": _due_state(record["due_utc"], now, settled),
                             "acknowledged": settled})
    checkins.sort(key=lambda c: (c["due_utc"], c["id"]))
    return {"operation_id": data["operation_id"], "title": data["title"], "objective": data["objective"],
            "revision": data["revision"], "created_utc": data["created_utc"],
            "aliases": aliases, "assignments": assignments, "checkins": checkins,
            "computed_utc": now.isoformat(),
            "basis": "Due states are computed from your machine clock and the UTC times you entered; "
                     "they are not trusted timestamps, and role labels are not access controls."}


def state_from(source, secret, now=None, assignee=None):
    """Current state, optionally narrowed to one assignee's assignments and check-ins.

    The assignee match is case-insensitive and exact against the name you entered
    (a role label is not an access control, so this is a view, not a permission).
    """
    data, _ = _load(source, secret)
    result = state(data, now)
    if assignee is not None:
        target = assignee.strip().lower()
        result["assignments"] = [a for a in result["assignments"] if a["assignee"].lower() == target]
        result["checkins"] = [c for c in result["checkins"] if c["assignee"].lower() == target]
        result["filtered_assignee"] = assignee
    return result


# --- iCal (.ics) export of due dates -----------------------------------------

def _ics_escape(text):
    return str(text).replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _ics_dt(iso):
    return _parse_utc(iso).astimezone(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ical(source, secret, now=None):
    """Render every assignment and check-in that has a due time as an iCal VEVENT."""
    data, _ = _load(source, secret)
    st = state(data, now)
    stamp = _ics_dt(st["computed_utc"])
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//ENVY//Ops Desk//EN", "CALSCALE:GREGORIAN"]

    def event(uid, due, summary, desc):
        lines.extend(["BEGIN:VEVENT", f"UID:{uid}@envy-ops-desk", f"DTSTAMP:{stamp}",
                      f"DTSTART:{_ics_dt(due)}", f"SUMMARY:{_ics_escape(summary)}",
                      f"DESCRIPTION:{_ics_escape(desc)}", "END:VEVENT"])

    for a in st["assignments"]:
        if a["due_utc"]:
            event(a["id"], a["due_utc"], f"{a['task']} ({a['assignee'] or 'unassigned'})",
                  f"assignment · {a['status']} · {a['due_state']}")
    for c in st["checkins"]:
        event(c["id"], c["due_utc"], f"{c['label']} ({c['assignee'] or 'unassigned'})",
              f"check-in · {c['due_state']}")
    lines.append("END:VCALENDAR")
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def write_ical(source, destination, secret, now=None):
    output = ical(source, secret, now)
    new_file(destination, output)
    return {"output": str(destination), "events": output.count(b"BEGIN:VEVENT"),
            "sha256": hashlib.sha256(output).hexdigest()}


def inspect(source, secret):
    data, envelope_hash = _load(source, secret)
    return {"operation_id": data["operation_id"], "title": data["title"], "objective": data["objective"],
            "revision": data["revision"], "created_utc": data["created_utc"],
            "envelope_sha256": envelope_hash, "previous_envelope_sha256": data["previous_envelope_sha256"],
            "records": [{"id": r["id"], "kind": r["kind"], "title": r["title"],
                         "assignee": r.get("assignee", ""), "status": r.get("status", ""),
                         "due_utc": r.get("due_utc", ""), "note": r.get("note", ""),
                         "role_label": r.get("role_label", ""), "references": r["references"],
                         "record_sha256": r["record_sha256"]} for r in data["records"]],
            "warning": "Record contents are decrypted for this display. Local times and role labels are "
                       "operator assertions, not trusted facts or access controls."}


# --- Authenticated handoff bundles -------------------------------------------
# A handoff is the same AES-256-GCM envelope wrapping a snapshot of the plan plus a
# note. It proves whoever sealed it knew the handoff passphrase; it establishes no
# sender identity. Importing re-encrypts the plan under the recipient's own passphrase.

def handoff_create(source, destination, secret, handoff_secret, note=""):
    data, envelope_hash = _load(source, secret)
    check_passphrase(handoff_secret)
    bundle = {"handoff_schema": 1, "created_utc": _utc(),
              "note": _text(note, "handoff note", 4000, required=False),
              "source_envelope_sha256": envelope_hash, "plan": data}
    payload = _canonical(bundle)
    if len(payload) + 128 > MAX_ENVELOPE:
        raise OpsDeskError("Handoff exceeds the 8 MiB encrypted limit")
    new_file(destination, encrypt_bytes(payload, handoff_secret))
    return {"output": str(destination), "operation_id": data["operation_id"], "revision": data["revision"],
            "records": len(data["records"]), "encrypted": True, "authenticated": True,
            "note": "A handoff proves the passphrase, not a sender identity."}


def _load_handoff(source, handoff_secret):
    encrypted = read_regular(source, MAX_ENVELOPE)
    try:
        bundle = json.loads(decrypt_bytes(encrypted, handoff_secret))
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise OpsDeskError("Handoff does not contain valid JSON") from None
    if not isinstance(bundle, dict) or bundle.get("handoff_schema") != 1 or set(bundle) != {
            "handoff_schema", "created_utc", "note", "source_envelope_sha256", "plan"}:
        raise OpsDeskError("Not an ENVY Ops Desk handoff bundle")
    _validate_plan(bundle["plan"])
    return bundle


def handoff_inspect(source, handoff_secret):
    bundle = _load_handoff(source, handoff_secret)
    plan = bundle["plan"]
    return {"handoff_created_utc": bundle["created_utc"], "note": bundle["note"],
            "operation_id": plan["operation_id"], "title": plan["title"], "objective": plan["objective"],
            "revision": plan["revision"], "records": len(plan["records"]),
            "source_envelope_sha256": bundle["source_envelope_sha256"],
            "warning": "A verified handoff proves the passphrase only; it does not establish who created it."}


def handoff_import(source, destination, handoff_secret, secret):
    """Decrypt a handoff and re-encrypt its plan, unchanged, under the local passphrase."""
    bundle = _load_handoff(source, handoff_secret)
    result = _write(destination, bundle["plan"], secret)
    return dict(result, imported_from_handoff=True, handoff_created_utc=bundle["created_utc"],
                note="The plan was re-encrypted under your passphrase; the handoff proves no sender identity.")


# --- Plaintext export --------------------------------------------------------

def export(source, destination, secret, format="html", now=None):
    if format not in ("html", "json"):
        raise OpsDeskError("Export format must be html or json")
    data, envelope_hash = _load(source, secret)
    view = state(data, now)
    report = {"plan": {k: data[k] for k in ("operation_id", "title", "objective", "created_utc", "revision")},
              "aliases": view["aliases"], "assignments": view["assignments"], "checkins": view["checkins"],
              "envelope_sha256": envelope_hash, "computed_utc": view["computed_utc"],
              "limitations": "Plaintext export. Due states come from the exporting machine's clock, role "
                             "labels are not access controls, and the hash chain does not independently "
                             "establish provenance, truth, or a trusted time."}
    if format == "json":
        output = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    else:
        def esc(value):
            return html.escape(str(value), quote=True)

        def rows(items, columns):
            head = "".join("<th>" + esc(label) + "</th>" for label, _ in columns)
            body = ""
            for item in items:
                body += "<tr>" + "".join("<td>" + esc(item.get(key, "")) + "</td>" for _, key in columns) + "</tr>"
            return "<table><thead><tr>" + head + "</tr></thead><tbody>" + body + "</tbody></table>"

        sections = (
            "<h2>Assignments</h2>" + rows(view["assignments"],
                [("Task", "task"), ("Assignee", "assignee"), ("Status", "status"),
                 ("Due UTC", "due_utc"), ("Due state", "due_state"), ("Progress", "progress_note")]) +
            "<h2>Check-ins</h2>" + rows(view["checkins"],
                [("Check-in", "label"), ("Assignee", "assignee"), ("Due UTC", "due_utc"),
                 ("Due state", "due_state"), ("Note", "note")]) +
            "<h2>Roles / aliases</h2>" + rows(view["aliases"],
                [("Alias", "alias"), ("Role label", "role_label"), ("Note", "note")]))
        # No external content, executable script, clickable operator-supplied URLs, or active HTML.
        output = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                  "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
                  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                  "<title>" + esc(data["title"]) + "</title><style>body{max-width:70rem;margin:2rem auto;padding:0 1rem;font:16px system-ui;line-height:1.5}"
                  "table{border-collapse:collapse;width:100%;margin:0 0 2rem}th,td{border:1px solid #777;padding:.4rem .6rem;text-align:left;vertical-align:top}"
                  "th{background:#eee}</style></head><body><h1>" + esc(data["title"]) + "</h1><p>" + esc(data["objective"]) +
                  "</p><p>" + esc(report["limitations"]) + "</p><p>Operation: " + esc(data["operation_id"]) +
                  " · Revision: " + str(data["revision"]) + " · Computed UTC: " + esc(view["computed_utc"]) +
                  "</p><p>Encrypted source SHA-256: " + envelope_hash + "</p>" + sections + "</body></html>").encode("utf-8")
    new_file(destination, output)
    return {"output": str(destination), "format": format, "plaintext": True,
            "sha256": hashlib.sha256(output).hexdigest(), "revision": data["revision"]}
