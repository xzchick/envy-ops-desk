"""A native ENVY Ops Desk window: a real desktop app, not a web view.

Built with PyQt6 and styled in the ENVY palette with a live animated header.
Create or open an encrypted plan, add role aliases, assignments, progress
updates, scheduled check-ins and acknowledgements, and watch computed due states.
Seal the plan into an authenticated handoff bundle, or import one. Every save
writes a new encrypted revision file; earlier revisions are never overwritten.

Nothing is sent: no messages, no background alerts, no network.
"""

from __future__ import annotations

import datetime
import math
import os
import sys
from pathlib import Path

from . import __version__
from . import core
from .core import OpsDeskError

BG = "#050713"
PANEL = "#0a0e22"
PANEL_HI = "#121735"
INK = "#f2f4ff"
MUTED = "#b9c3df"
DIM = "#6f7898"
PINK = "#ff3db4"
CYAN = "#35e8ff"
LAVENDER = "#ac8cff"
VIOLET = "#8547e8"
AMBER = "#ffb347"
GREEN = "#49e3a6"
LINE = "#1f2547"

# Each record kind's accent colour.
KIND_ACCENT = {"alias": PINK, "assignment": CYAN, "progress": VIOLET,
               "checkin": LAVENDER, "acknowledgement": GREEN}
# Due-state colours shared by every table.
DUE_COLOR = {"overdue": PINK, "due soon": AMBER, "scheduled": CYAN,
             "settled": GREEN, "no due time": DIM}
STATUS_COLOR = {"todo": MUTED, "doing": CYAN, "blocked": PINK, "done": GREEN}


def lerp(a, b, t):
    from PyQt6.QtGui import QColor
    ca, cb = QColor(a), QColor(b)
    return QColor(int(ca.red() + (cb.red() - ca.red()) * t),
                  int(ca.green() + (cb.green() - ca.green()) * t),
                  int(ca.blue() + (cb.blue() - ca.blue()) * t))


def normalize_utc(text):
    """Accept friendly input and return an ISO-8601 UTC string, or '' for empty.

    'now' → the current time; a bare 'YYYY-MM-DD HH:MM' is read as UTC. Anything
    else is handed to the core validator unchanged, which rejects non-UTC input.
    """
    value = (text or "").strip()
    if not value:
        return ""
    if value.lower() == "now":
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    value = value.replace(" ", "T", 1)
    if "+" not in value and not value.endswith("Z") and value.count("-") <= 2:
        value += "+00:00"
    return value


def _build():
    from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF
    from PyQt6.QtGui import (QColor, QPainter, QLinearGradient, QRadialGradient, QFont,
                             QPen, QBrush)
    from PyQt6.QtWidgets import (QApplication, QWidget, QLabel, QPushButton, QPlainTextEdit,
                                 QLineEdit, QComboBox, QTabWidget, QTableWidget, QTableWidgetItem,
                                 QHeaderView, QAbstractItemView, QVBoxLayout, QHBoxLayout,
                                 QFormLayout, QInputDialog, QFileDialog, QMessageBox,
                                 QLineEdit as QLE)

    class Header(QWidget):
        def __init__(self):
            super().__init__()
            self.setFixedHeight(172)
            self.phase = 0.0
            self.stars = [(((i * 139 + 37) % 1000) / 1000.0,
                           ((i * 83 + 19) % 172) / 172.0,
                           0.6 + (i % 3) * 0.5, (i % 7) / 7.0) for i in range(60)]

        def tick(self, phase):
            self.phase = phase
            self.update()

        def paintEvent(self, _event):
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            w, h = self.width(), self.height()
            p.fillRect(self.rect(), QColor(BG))
            for cx, cy, rad, col, a in ((w - 120, 60, 250, VIOLET, 60),
                                        (60, h, 280, CYAN, 52), (w * 0.5, -40, 240, PINK, 42)):
                g = QRadialGradient(cx, cy, rad)
                c = QColor(col); c.setAlpha(a); g.setColorAt(0, c)
                c2 = QColor(col); c2.setAlpha(0); g.setColorAt(1, c2)
                p.setBrush(QBrush(g)); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(cx, cy), rad, rad)
            for sx, sy, sr, ph in self.stars:
                tw = 0.5 + 0.5 * math.sin(self.phase / 0.5 + ph * 6.28)
                c = QColor(205, 217, 255); c.setAlphaF(0.15 + 0.6 * tw)
                p.setBrush(c); p.setPen(Qt.PenStyle.NoPen)
                p.drawEllipse(QPointF(sx * w, sy * h), sr, sr)
            pulse = 0.5 + 0.5 * math.sin(self.phase)
            p.setFont(QFont("Helvetica", 22))
            p.setPen(QColor(CYAN) if pulse > 0.5 else QColor(PINK))
            p.drawText(QRectF(22, 28, 44, 44), Qt.AlignmentFlag.AlignCenter, "▦")
            p.setFont(QFont("Helvetica", 37, QFont.Weight.Bold))
            grad = QLinearGradient(70, 0, 500, 0)
            grad.setColorAt(0, QColor(CYAN))
            grad.setColorAt(0.5, QColor(lerp(CYAN, "#ffffff", 0.2 * pulse)))
            grad.setColorAt(1, QColor(PINK))
            glow = QColor(VIOLET); glow.setAlpha(int(55 + 55 * pulse))
            p.setPen(QPen(glow, 1))
            for dx, dy in ((1.3, 1.3), (-1.3, 1.3), (1.3, -1.3)):
                p.drawText(QRectF(70 + dx, 34 + dy, 600, 52), Qt.AlignmentFlag.AlignVCenter, "ENVY OPS DESK")
            p.setPen(QPen(QBrush(grad), 1))
            p.drawText(QRectF(70, 34, 600, 52), Qt.AlignmentFlag.AlignVCenter, "ENVY OPS DESK")
            p.setFont(QFont("Courier New", 11, QFont.Weight.Bold))
            p.setPen(QColor(LAVENDER))
            p.drawText(QRectF(74, 90, 600, 20), Qt.AlignmentFlag.AlignVCenter,
                       "ENCRYPTED  ·  LOCAL  ·  REVISION-PRESERVING")
            y = 126
            p.setPen(QPen(QColor(LINE), 2)); p.drawLine(74, y, w - 54, y)
            p.setPen(QPen(QColor(VIOLET), 3)); p.drawLine(74, y, 146, y)
            span = (w - 54) - 74
            x = 74 + span * ((self.phase * 0.12) % 1.0)
            halo = QRadialGradient(x, y, 15)
            hc = QColor(CYAN); hc.setAlpha(170); halo.setColorAt(0, hc)
            hc2 = QColor(CYAN); hc2.setAlpha(0); halo.setColorAt(1, hc2)
            p.setBrush(QBrush(halo)); p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(x, y), 15, 15)
            p.setBrush(QColor("#ffffff")); p.drawEllipse(QPointF(x, y), 2.5, 2.5)
            p.end()

    def make_table(headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setDefaultSectionSize(30)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        return table

    class Window(QWidget):
        def __init__(self):
            super().__init__()
            self.source = None     # Path of the current encrypted revision
            self.secret = None     # passphrase bytes, kept in memory for this plan only
            self.data = None       # decrypted, validated plan dict
            self.setWindowTitle("ENVY Ops Desk")
            self.resize(1180, 900)
            self.setMinimumSize(960, 760)
            self.setStyleSheet(STYLE)
            root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
            self.header = Header(); root.addWidget(self.header)

            body = QWidget(); body.setObjectName("body")
            bl = QVBoxLayout(body); bl.setContentsMargins(22, 14, 22, 16); bl.setSpacing(10)

            intro = QLabel("Plan assignments, roles and check-ins locally. Each save creates a new "
                           "encrypted revision. No messages or background alerts are sent.")
            intro.setObjectName("status"); intro.setWordWrap(True); bl.addWidget(intro)

            controls = QHBoxLayout()
            for caption, handler, name in (("New plan", self.new_plan, "go"),
                                           ("Open plan", self.open_plan, "pick"),
                                           ("Lock", self.lock, "pick"),
                                           ("Create handoff", self.create_handoff, "pick"),
                                           ("Import handoff", self.import_handoff, "pick"),
                                           ("Refresh due states", self.refresh_views, "pick")):
                b = QPushButton(caption); b.setObjectName(name)
                b.setCursor(Qt.CursorShape.PointingHandCursor); b.clicked.connect(handler)
                controls.addWidget(b)
            controls.addStretch(1)
            bl.addLayout(controls)

            self.plan_header = QPlainTextEdit(); self.plan_header.setObjectName("mono")
            self.plan_header.setReadOnly(True); self.plan_header.setFixedHeight(90)
            self.plan_header.setPlainText("No plan open. Create a new encrypted plan or open an existing one.")
            bl.addWidget(self.plan_header)

            self.views = QTabWidget(); self.views.setObjectName("tabs")
            self.t_assign = make_table(["Task", "Assignee", "Status", "Due UTC", "Due state", "Progress note"])
            self.t_check = make_table(["Check-in", "Assignee", "Due UTC", "Due state", "Note"])
            self.t_alias = make_table(["Alias", "Role label", "Note"])
            self.views.addTab(self.t_assign, "Assignments")
            self.views.addTab(self.t_check, "Check-ins")
            self.views.addTab(self.t_alias, "Roles / aliases")
            bl.addWidget(self.views, 3)

            self.forms = QTabWidget(); self.forms.setObjectName("tabs")
            self.forms.addTab(self._alias_form(), "Add alias")
            self.forms.addTab(self._assignment_form(), "Add assignment")
            self.forms.addTab(self._progress_form(), "Update progress")
            self.forms.addTab(self._checkin_form(), "Schedule check-in")
            self.forms.addTab(self._ack_form(), "Acknowledge")
            bl.addWidget(self.forms, 2)

            self.path_label = QLabel(""); self.path_label.setObjectName("foot")
            self.path_label.setWordWrap(True); bl.addWidget(self.path_label)
            foot = QLabel("Roles are labels, not access controls. Handoffs use authenticated passphrase "
                          "encryption; they do not establish a sender identity. Open plans remain in process "
                          "memory until lock or close; Python cannot guarantee memory erasure.")
            foot.setObjectName("foot"); foot.setWordWrap(True); bl.addWidget(foot)
            root.addWidget(body, 1)

            self.phase = 0.0
            self.timer = QTimer(self); self.timer.timeout.connect(self._animate); self.timer.start(33)
            self._set_enabled(False)

        # ----- add-record forms --------------------------------------------
        def _field(self):
            w = QLineEdit(); w.setObjectName("field"); return w

        def _status_box(self):
            box = QComboBox(); box.addItems(list(core.STATUSES)); return box

        def _submit_row(self, caption, handler):
            row = QHBoxLayout()
            btn = QPushButton(caption); btn.setObjectName("go")
            btn.setCursor(Qt.CursorShape.PointingHandCursor); btn.clicked.connect(handler)
            status = QLabel(""); status.setObjectName("status")
            row.addWidget(btn); row.addWidget(status, 1)
            return row, status

        def _alias_form(self):
            tab = QWidget(); form = QFormLayout(tab); form.setSpacing(8)
            self.a_alias = self._field(); self.a_role = self._field(); self.a_note = self._field()
            form.addRow(self._tag("Alias"), self.a_alias)
            form.addRow(self._tag("Role label"), self.a_role)
            form.addRow(self._tag("Note (optional)"), self.a_note)
            row, self.a_status = self._submit_row("Add alias in a new revision", self.add_alias)
            form.addRow(row)
            return tab

        def _assignment_form(self):
            tab = QWidget(); form = QFormLayout(tab); form.setSpacing(8)
            self.g_task = self._field(); self.g_assignee = self._field()
            self.g_status = self._status_box(); self.g_due = self._field(); self.g_note = self._field()
            self.g_due.setPlaceholderText("2026-11-06T16:00:00+00:00  ·  'now'  ·  blank for none")
            form.addRow(self._tag("Task"), self.g_task)
            form.addRow(self._tag("Assignee"), self.g_assignee)
            form.addRow(self._tag("Status"), self.g_status)
            form.addRow(self._tag("Due UTC (optional)"), self.g_due)
            form.addRow(self._tag("Progress note (optional)"), self.g_note)
            row, self.g_status_msg = self._submit_row("Add assignment in a new revision", self.add_assignment)
            form.addRow(row)
            return tab

        def _progress_form(self):
            tab = QWidget(); form = QFormLayout(tab); form.setSpacing(8)
            self.p_target = QComboBox(); self.p_status = self._status_box(); self.p_note = self._field()
            form.addRow(self._tag("Assignment"), self.p_target)
            form.addRow(self._tag("New status"), self.p_status)
            form.addRow(self._tag("Progress note"), self.p_note)
            row, self.p_status_msg = self._submit_row("Record progress in a new revision", self.add_progress)
            form.addRow(row)
            return tab

        def _checkin_form(self):
            tab = QWidget(); form = QFormLayout(tab); form.setSpacing(8)
            self.c_label = self._field(); self.c_assignee = self._field()
            self.c_due = self._field(); self.c_note = self._field()
            self.c_due.setPlaceholderText("2026-11-06T16:00:00+00:00  ·  'now'")
            form.addRow(self._tag("Check-in"), self.c_label)
            form.addRow(self._tag("Assignee (optional)"), self.c_assignee)
            form.addRow(self._tag("Due UTC"), self.c_due)
            form.addRow(self._tag("Note (optional)"), self.c_note)
            row, self.c_status_msg = self._submit_row("Schedule check-in in a new revision", self.add_checkin)
            form.addRow(row)
            return tab

        def _ack_form(self):
            tab = QWidget(); form = QFormLayout(tab); form.setSpacing(8)
            self.k_target = QComboBox(); self.k_title = self._field(); self.k_note = self._field()
            self.k_title.setText("Acknowledged")
            form.addRow(self._tag("Record"), self.k_target)
            form.addRow(self._tag("Title"), self.k_title)
            form.addRow(self._tag("Note (optional)"), self.k_note)
            row, self.k_status_msg = self._submit_row("Acknowledge in a new revision", self.add_ack)
            form.addRow(row)
            return tab

        def _tag(self, text):
            lab = QLabel(text); lab.setObjectName("tag"); return lab

        # ----- plan lifecycle ----------------------------------------------
        def _ask_passphrase(self, confirm, prompt="Plan passphrase (at least 12 characters):",
                            title="Passphrase"):
            text, ok = QInputDialog.getText(self, title, prompt, QLE.EchoMode.Password)
            if not ok:
                return None
            secret = text.encode("utf-8")
            if confirm:
                again, ok2 = QInputDialog.getText(self, "Confirm passphrase",
                                                  "Repeat the passphrase:", QLE.EchoMode.Password)
                if not ok2:
                    return None
                if again.encode("utf-8") != secret:
                    self._warn("Passphrases do not match."); return None
            try:
                return core.check_passphrase(secret)
            except OpsDeskError as exc:
                self._warn(str(exc)); return None

        def new_plan(self):
            title, ok = QInputDialog.getText(self, "New plan", "Plan title:")
            if not ok or not title.strip():
                return
            objective, ok2 = QInputDialog.getText(self, "Objective", "One-line objective (optional):")
            if not ok2:
                return
            dest, _ = QFileDialog.getSaveFileName(self, "Create encrypted plan", "plan.envyops",
                                                  "Encrypted plan (*.envyops);;All files (*)")
            if not dest:
                return
            secret = self._ask_passphrase(confirm=True)
            if secret is None:
                return
            try:
                if Path(dest).exists():
                    Path(dest).unlink()  # the save dialog already confirmed the name
                core.create(dest, title.strip(), secret, objective.strip())
                self._open_path(Path(dest), secret)
            except (OpsDeskError, OSError) as exc:
                self._warn(str(exc))

        def open_plan(self):
            path, _ = QFileDialog.getOpenFileName(self, "Open encrypted plan", "",
                                                  "Encrypted plan (*.envyops);;All files (*)")
            if not path:
                return
            secret = self._ask_passphrase(confirm=False)
            if secret is None:
                return
            self._open_path(Path(path), secret)

        def _open_path(self, path, secret):
            try:
                data, _ = core._load(path, secret)
            except OpsDeskError as exc:
                self._warn(str(exc)); return
            self.source, self.secret, self.data = path, secret, data
            self._set_enabled(True)
            self.refresh_views()

        def lock(self):
            self.source = self.secret = self.data = None
            for table in (self.t_assign, self.t_check, self.t_alias):
                table.setRowCount(0)
            self.plan_header.setPlainText("Locked. The passphrase was cleared from memory.")
            self.path_label.setText("")
            self._refresh_targets()
            self._set_enabled(False)

        # ----- handoffs -----------------------------------------------------
        def create_handoff(self):
            if not self.data:
                return
            note, ok = QInputDialog.getText(self, "Create handoff", "Note to the recipient (optional):")
            if not ok:
                return
            handoff_secret = self._ask_passphrase(confirm=True, title="Handoff passphrase",
                                                  prompt="Handoff passphrase (shared with the recipient):")
            if handoff_secret is None:
                return
            dest, _ = QFileDialog.getSaveFileName(self, "Write authenticated handoff", "handoff.envyho",
                                                  "Handoff bundle (*.envyho);;All files (*)")
            if not dest:
                return
            try:
                if Path(dest).exists():
                    Path(dest).unlink()
                result = core.handoff_create(self.source, dest, self.secret, handoff_secret, note.strip())
            except (OpsDeskError, OSError) as exc:
                self._warn(str(exc)); return
            self._warn(f"Sealed an authenticated handoff at {result['output']}.\n\n"
                       "A handoff proves the passphrase, not a sender identity. Share the bundle and the "
                       "passphrase over separate channels.",
                       icon=QMessageBox.Icon.Information, title="Handoff created")

        def import_handoff(self):
            path, _ = QFileDialog.getOpenFileName(self, "Import handoff", "",
                                                  "Handoff bundle (*.envyho);;All files (*)")
            if not path:
                return
            handoff_secret = self._ask_passphrase(confirm=False, title="Handoff passphrase",
                                                  prompt="Handoff passphrase:")
            if handoff_secret is None:
                return
            plan_secret = self._ask_passphrase(confirm=True, title="New plan passphrase",
                                               prompt="New passphrase for your local plan copy:")
            if plan_secret is None:
                return
            dest, _ = QFileDialog.getSaveFileName(self, "Save imported plan", "imported.envyops",
                                                  "Encrypted plan (*.envyops);;All files (*)")
            if not dest:
                return
            try:
                if Path(dest).exists():
                    Path(dest).unlink()
                core.handoff_import(path, dest, handoff_secret, plan_secret)
            except (OpsDeskError, OSError) as exc:
                self._warn(str(exc)); return
            self._open_path(Path(dest), plan_secret)
            self._warn("Imported the handoff into a new local plan, re-encrypted under your passphrase. "
                       "The handoff proved the passphrase only — not who created it.",
                       icon=QMessageBox.Icon.Information, title="Handoff imported")

        # ----- appends ------------------------------------------------------
        def _append(self, value, status_label):
            if not self.data:
                return
            dest = self._next_revision_path()
            try:
                result = core.append_record(self.source, dest, value, self.secret)
            except (OpsDeskError, OSError) as exc:
                status_label.setText(str(exc)); status_label.setStyleSheet(f"#status{{color:{PINK};}}")
                return
            self.source = Path(result["output"])
            self.data, _ = core._load(self.source, self.secret)
            self.refresh_views()
            status_label.setText(f"Saved revision {result['revision']} → {Path(result['output']).name}")
            status_label.setStyleSheet(f"#status{{color:{CYAN};}}")

        def add_alias(self):
            value = {"kind": "alias", "title": self.a_alias.text().strip()}
            if self.a_role.text().strip():
                value["role_label"] = self.a_role.text().strip()
            if self.a_note.text().strip():
                value["note"] = self.a_note.text().strip()
            self._append(value, self.a_status)
            if self.data:
                self.a_alias.clear(); self.a_role.clear(); self.a_note.clear()

        def add_assignment(self):
            value = {"kind": "assignment", "title": self.g_task.text().strip(),
                     "status": self.g_status.currentText()}
            if self.g_assignee.text().strip():
                value["assignee"] = self.g_assignee.text().strip()
            if self.g_due.text().strip():
                value["due_utc"] = normalize_utc(self.g_due.text())
            if self.g_note.text().strip():
                value["note"] = self.g_note.text().strip()
            self._append(value, self.g_status_msg)
            if self.data:
                self.g_task.clear(); self.g_assignee.clear(); self.g_due.clear(); self.g_note.clear()

        def add_progress(self):
            target = self.p_target.currentData()
            if not target:
                self.p_status_msg.setText("Add an assignment first."); return
            value = {"kind": "progress", "title": "Progress update", "status": self.p_status.currentText(),
                     "references": [target]}
            if self.p_note.text().strip():
                value["note"] = self.p_note.text().strip()
            self._append(value, self.p_status_msg)
            if self.data:
                self.p_note.clear()

        def add_checkin(self):
            value = {"kind": "checkin", "title": self.c_label.text().strip(),
                     "due_utc": normalize_utc(self.c_due.text())}
            if self.c_assignee.text().strip():
                value["assignee"] = self.c_assignee.text().strip()
            if self.c_note.text().strip():
                value["note"] = self.c_note.text().strip()
            self._append(value, self.c_status_msg)
            if self.data:
                self.c_label.clear(); self.c_assignee.clear(); self.c_due.clear(); self.c_note.clear()

        def add_ack(self):
            target = self.k_target.currentData()
            if not target:
                self.k_status_msg.setText("Nothing to acknowledge yet."); return
            value = {"kind": "acknowledgement", "title": self.k_title.text().strip() or "Acknowledged",
                     "references": [target]}
            if self.k_note.text().strip():
                value["note"] = self.k_note.text().strip()
            self._append(value, self.k_status_msg)
            if self.data:
                self.k_note.clear()

        # ----- display ------------------------------------------------------
        def refresh_views(self):
            if not self.data:
                return
            view = core.state(self.data)
            self.plan_header.setPlainText(
                f"{view['title']}  ·  revision {view['revision']}\n"
                f"{view['objective'] or '(no objective recorded)'}\n"
                f"Operation: {view['operation_id']}")
            self._fill_assignments(view["assignments"])
            self._fill_checkins(view["checkins"])
            self._fill_aliases(view["aliases"])
            self._refresh_targets()
            if self.source:
                self.path_label.setText(str(self.source))

        def _cell(self, text, color=None):
            item = QTableWidgetItem("" if text is None else str(text))
            if color:
                item.setForeground(QColor(color))
            return item

        def _fill_assignments(self, rows):
            t = self.t_assign; t.setRowCount(len(rows))
            for i, r in enumerate(rows):
                t.setItem(i, 0, self._cell(r["task"], CYAN))
                t.setItem(i, 1, self._cell(r["assignee"]))
                t.setItem(i, 2, self._cell(r["status"], STATUS_COLOR.get(r["status"], INK)))
                t.setItem(i, 3, self._cell(r["due_utc"]))
                t.setItem(i, 4, self._cell(r["due_state"], DUE_COLOR.get(r["due_state"], INK)))
                t.setItem(i, 5, self._cell(r["progress_note"]))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)

        def _fill_checkins(self, rows):
            t = self.t_check; t.setRowCount(len(rows))
            for i, r in enumerate(rows):
                t.setItem(i, 0, self._cell(r["label"], LAVENDER))
                t.setItem(i, 1, self._cell(r["assignee"]))
                t.setItem(i, 2, self._cell(r["due_utc"]))
                t.setItem(i, 3, self._cell(r["due_state"], DUE_COLOR.get(r["due_state"], INK)))
                t.setItem(i, 4, self._cell(r["note"]))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)

        def _fill_aliases(self, rows):
            t = self.t_alias; t.setRowCount(len(rows))
            for i, r in enumerate(rows):
                t.setItem(i, 0, self._cell(r["alias"], PINK))
                t.setItem(i, 1, self._cell(r["role_label"]))
                t.setItem(i, 2, self._cell(r["note"]))
            t.resizeColumnsToContents(); t.horizontalHeader().setStretchLastSection(True)

        def _refresh_targets(self):
            self.p_target.clear(); self.k_target.clear()
            if not self.data:
                return
            for r in self.data["records"]:
                if r["kind"] == "assignment":
                    self.p_target.addItem(f"{r['title']}  ({r['id'][:8]})", r["id"])
            for r in self.data["records"]:
                if r["kind"] in ("assignment", "checkin"):
                    self.k_target.addItem(f"[{r['kind']}] {r['title']}  ({r['id'][:8]})", r["id"])

        def _next_revision_path(self):
            base = self.source
            stem = base.stem
            if ".r" in stem and stem.rsplit(".r", 1)[-1].isdigit():
                stem = stem.rsplit(".r", 1)[0]
            rev = (self.data["revision"] + 1) if self.data else 1
            candidate = base.with_name(f"{stem}.r{rev}{base.suffix}")
            n = rev
            while candidate.exists():
                n += 1
                candidate = base.with_name(f"{stem}.r{n}{base.suffix}")
            return candidate

        def _set_enabled(self, on):
            for w in (self.views, self.forms):
                w.setEnabled(on)

        def _warn(self, message, icon=None, title="Ops Desk"):
            box = QMessageBox(self); box.setWindowTitle(title)
            box.setIcon(icon or QMessageBox.Icon.Warning); box.setText(message); box.exec()

        def _animate(self):
            self.phase += 0.05
            self.header.tick(self.phase)

    return QApplication, Window


STYLE = f"""
#body {{ background: {BG}; }}
QWidget {{ color: {INK}; font-family: Helvetica, Arial, sans-serif; font-size: 13px; }}
#tag {{ color: {MUTED}; font-weight: bold; font-size: 11px; letter-spacing: 1px; }}
#status {{ color: {MUTED}; font-size: 12px; }}
#foot {{ color: {DIM}; font-size: 11px; }}
#mono {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 9px; color: {INK};
         font-family: "Courier New", monospace; font-size: 13px; padding: 8px; }}
#field {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 8px; color: {INK}; padding: 7px 9px; }}
#field:focus {{ border: 1px solid {CYAN}; }}
QComboBox {{ background: {PANEL_HI}; border: 1px solid {LINE}; border-radius: 8px; color: {INK}; padding: 6px 10px; }}
QComboBox QAbstractItemView {{ background: {PANEL}; color: {INK}; selection-background-color: {VIOLET}; }}
QTableWidget {{ background: {PANEL_HI}; alternate-background-color: {PANEL}; border: 1px solid {LINE};
                border-radius: 10px; gridline-color: {LINE}; }}
QTableWidget::item {{ padding: 4px 6px; }}
QTableWidget::item:selected {{ background: {VIOLET}; color: {INK}; }}
QHeaderView::section {{ background: {PANEL}; color: {MUTED}; padding: 6px 8px; border: none;
                        border-bottom: 1px solid {LINE}; font-weight: bold; }}
QTableCornerButton::section {{ background: {PANEL}; border: none; }}
QTabWidget#tabs::pane {{ border: 1px solid {LINE}; border-radius: 12px; background: {PANEL}; }}
QTabBar::tab {{ background: {PANEL_HI}; color: {MUTED}; padding: 8px 18px; margin-right: 6px;
                border-top-left-radius: 9px; border-top-right-radius: 9px; font-weight: bold; }}
QTabBar::tab:selected {{ color: {INK}; border-bottom: 2px solid {PINK}; }}
QPushButton#go {{ background: {PINK}; color: {BG}; border: none; border-radius: 10px; font-weight: bold; padding: 9px 18px; }}
QPushButton#go:hover {{ background: {CYAN}; }}
QPushButton#pick {{ background: {PANEL_HI}; border: 1px solid {LAVENDER}; border-radius: 9px; color: {INK};
                    font-weight: bold; padding: 9px 14px; }}
QPushButton#pick:hover {{ background: #1b2150; }}
"""


def run_app() -> int:
    try:
        from PyQt6.QtWidgets import QApplication  # noqa: F401
    except Exception:
        print("PyQt6 is required for the Ops Desk window. Use 'envy-ops-desk' subcommands in a terminal instead.")
        return 2
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print("No display found. Use 'envy-ops-desk new/add/state/export' in a terminal instead.")
        return 2
    try:
        QApplication, Window = _build()
        app = QApplication.instance() or QApplication(sys.argv)
        window = Window(); window.show()
        return app.exec()
    except Exception as exc:  # pragma: no cover
        print(f"Could not open the window: {exc}")
        return 2
