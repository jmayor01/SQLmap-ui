#!/usr/bin/env python3
"""
sqlmap-ui — a friendly terminal UI for a locally installed sqlmap.

Build sqlmap command lines from a form, run sqlmap for you, and watch its live,
colorized output. Includes one-click scan presets, a live command preview,
clipboard paste/copy, output saving, and remembered settings.

For authorized security testing only.

Run:        python sqlmap_ui.py
Configure:  set SQLMAP_PATH to your sqlmap binary if it isn't on PATH, e.g.
            Windows: set SQLMAP_PATH=python C:\\sqlmap\\sqlmap.py
            Linux:   SQLMAP_PATH="python /opt/sqlmap/sqlmap.py" python sqlmap_ui.py
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TextArea,
)

SQLMAP_PATH = os.environ.get("SQLMAP_PATH", "sqlmap")
CONFIG_FILE = Path.home() / ".sqlmap_ui.json"


# ---------------------------------------------------------------------------
# Clipboard & sqlmap discovery (no third-party dependencies)
# ---------------------------------------------------------------------------
def read_clipboard() -> str | None:
    """Read the OS clipboard as text. Returns None if it can't be read."""
    if os.name == "nt":
        candidates = [["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"]]
    else:
        candidates = [
            ["pbpaste"],
            ["wl-paste", "--no-newline"],
            ["xclip", "-selection", "clipboard", "-o"],
            ["xsel", "--clipboard", "--output"],
        ]
    for cmd in candidates:
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            continue
        if out.returncode == 0 and out.stdout:
            return out.stdout
    return None


def write_clipboard(text: str) -> bool:
    """Write text to the OS clipboard. Returns True on success."""
    if os.name == "nt":
        candidates = [["clip"]]
    else:
        candidates = [
            ["pbcopy"],
            ["wl-copy"],
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
        ]
    for cmd in candidates:
        try:
            p = subprocess.run(cmd, input=text, text=True, timeout=5)
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0:
            return True
    return False


def destructive_reason(argv: list[str]) -> str | None:
    """Return a reason string if the command could DELETE/destroy data, else None.

    sqlmap only deletes data when the operator supplies destructive SQL or opens
    an OS/SQL shell. Reading data (--dump, --passwords) is not destructive. This
    guard enforces the "never delete data" rule for both form and custom runs.
    """
    import re
    low_tokens = [a.lower() for a in argv]

    # Flags that grant arbitrary command/SQL execution on the target.
    for f in ("--os-shell", "--os-pwn", "--os-cmd", "--sql-shell"):
        if any(t == f or t.startswith(f + "=") for t in low_tokens):
            return (f"{f} can run arbitrary commands on the target, which could "
                    "delete data")

    def looks_destructive(sql: str) -> bool:
        return bool(
            re.search(r"\b(drop|delete|truncate|alter)\b", sql, re.I)
            or re.search(r"\bupdate\b[\s\S]*\bset\b", sql, re.I)
        )

    # Inspect the value of any SQL-query flag (inline "=val" or next token).
    for i, a in enumerate(argv):
        al = a.lower()
        if al.startswith("--sql-query") or al == "-q":
            val = a.split("=", 1)[1] if "=" in a else (
                argv[i + 1] if i + 1 < len(argv) else "")
            if looks_destructive(val):
                return ("the SQL query looks destructive (DROP/DELETE/TRUNCATE/"
                        "ALTER/UPDATE)")
    return None


def resolve_sqlmap_cmd() -> list[str] | None:
    """Return the sqlmap command as a token list, or None if not found."""
    parts = shlex.split(SQLMAP_PATH, posix=(os.name != "nt"))
    if not parts:
        return None
    if len(parts) > 1:  # e.g. "python /opt/sqlmap/sqlmap.py"
        return parts
    if shutil.which(parts[0]):
        return parts
    return None


# ---------------------------------------------------------------------------
# Flag maps, presets
# ---------------------------------------------------------------------------
BOOL_FLAGS = {
    "dbs": "--dbs",
    "tables": "--tables",
    "columns": "--columns",
    "dump": "--dump",
    "current_user": "--current-user",
    "current_db": "--current-db",
    "is_dba": "--is-dba",
    "passwords": "--passwords",
    "forms": "--forms",
}
BOOL_LABELS = {
    "dbs": "Enumerate databases",
    "tables": "List tables",
    "columns": "List columns",
    "dump": "Dump table data",
    "current_user": "Current DB user",
    "current_db": "Current database",
    "is_dba": "Is DBA?",
    "passwords": "Dump password hashes",
    "forms": "Test forms on page",
}
VALUE_FLAGS = {
    "data": "--data",
    "cookie": "--cookie",
    "level": "--level",
    "risk": "--risk",
    "threads": "--threads",
    "db": "-D",
    "tbl": "-T",
    "col": "-C",
    "proxy": "--proxy",
}

# One-click scan profiles. These only READ from the target (detect, enumerate,
# read password hashes); none of them modify or delete data. A separate guard
# (destructive_reason) blocks any data-destroying command regardless of preset.
PRESETS = {
    "quick": {
        "desc": "Just detect if the parameter is injectable (fast).",
        "level": "1", "risk": "1", "checks": [],
    },
    "standard": {
        "desc": "Detect + basic DB info (user, current db, DBA, databases).",
        "level": "1", "risk": "1",
        "checks": ["dbs", "current_user", "current_db", "is_dba"],
    },
    "enumerate": {
        "desc": "Map out databases, tables and columns.",
        "level": "2", "risk": "1",
        "checks": ["dbs", "tables", "columns"],
    },
    "full": {
        "desc": "Full recon: databases, tables, columns, user/DBA info, and "
                "password hashes for cracking. Never deletes data.",
        "level": "2", "risk": "1",
        "checks": ["dbs", "tables", "columns",
                   "current_user", "current_db", "is_dba", "passwords"],
    },
}

# Fields saved/restored between sessions.
SAVED_INPUTS = ["url", "data", "cookie", "level", "risk", "threads",
                "db", "tbl", "col", "proxy", "extra", "req_path"]


class SqlmapUI(App):
    CSS = """
    Screen { layout: horizontal; }

    #sidebar { width: 48; border-right: solid $primary; padding: 1 2; }
    #sidebar Label { color: $text-muted; margin-top: 1; }
    .hint { color: $text-muted; text-style: italic; margin: 0; }
    .row { height: auto; }
    .row Input { width: 1fr; margin-right: 1; }
    #presets { height: auto; margin-top: 1; }
    #presets Button { min-width: 0; width: 1fr; margin-right: 1; }
    #actions Static { color: $accent; text-style: bold; margin-top: 1; }
    Checkbox { height: 1; border: none; padding: 0; }
    #paste_clip { margin-top: 1; width: 100%; }

    #main { width: 1fr; }
    #cmdline {
        height: auto; min-height: 1; padding: 0 1; background: $panel;
        color: $text-muted; border-bottom: solid $primary;
    }
    #cmd_edit { display: none; margin: 0 1; border: tall $accent; }
    #log { padding: 0 1; }
    #status { height: 1; padding: 0 1; background: $panel-darken-1; }
    #buttons { height: auto; padding: 1 1; align: left middle; }
    #buttons Button { margin-right: 1; }
    """

    BINDINGS = [
        ("ctrl+r", "run", "Run"),
        ("ctrl+s", "stop", "Stop"),
        ("ctrl+b", "paste_clipboard", "Paste req"),
        ("ctrl+e", "copy_output", "Copy out"),
        ("ctrl+o", "save_output", "Save out"),
        ("ctrl+l", "clear", "Clear"),
        ("f1", "help", "sqlmap opts"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.proc: subprocess.Popen | None = None
        self._stop = False
        self._req_file: str | None = None
        self._raw_lines: list[str] = []
        self._scan_start: float | None = None
        self._custom_mode = False
        self._preview_cmd = ""

    # ---------------------------------------------------------------- layout
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with VerticalScroll(id="sidebar"):
            yield Label("Target URL")
            yield Input(placeholder="http://host/page.php?id=1", id="url")

            with Collapsible(title="Paste raw HTTP request (-r)", id="req_box"):
                yield Label("Paste a full request (e.g. from Burp). "
                            "Overrides the URL above.")
                yield TextArea(id="request", language=None, soft_wrap=True)
                yield Button("📋 Paste from clipboard", id="paste_clip")
                yield Label("…or load the request from a saved file:")
                yield Input(placeholder=r"C:\path\to\request.txt", id="req_path")

            yield Static("PRESETS", id="preset_head")
            with Horizontal(id="presets"):
                yield Button("Quick", id="p_quick")
                yield Button("Standard", id="p_standard")
                yield Button("Enum", id="p_enumerate")
                yield Button("Full", id="p_full")
            yield Static("Presets only read data; the tool blocks anything "
                         "that could delete data.", classes="hint")

            yield Label("POST data (optional)")
            yield Input(placeholder="id=1&name=test", id="data")
            yield Label("Cookie (optional)")
            yield Input(placeholder="PHPSESSID=...", id="cookie")

            with Horizontal(classes="row"):
                with Vertical():
                    yield Label("Level 1-5")
                    yield Input(placeholder="1", id="level")
                with Vertical():
                    yield Label("Risk 1-3")
                    yield Input(placeholder="1", id="risk")
                with Vertical():
                    yield Label("Threads")
                    yield Input(placeholder="1", id="threads")
            yield Static("Higher level/risk = more thorough but slower.",
                         classes="hint")

            yield Label("DBMS")
            yield Select(
                [(n, n) for n in
                 ("auto-detect", "MySQL", "PostgreSQL", "Microsoft SQL Server",
                  "Oracle", "SQLite", "MariaDB")],
                value="auto-detect", id="dbms", allow_blank=False,
            )

            with Vertical(id="actions"):
                yield Static("ACTIONS")
                for key, label in BOOL_LABELS.items():
                    yield Checkbox(label, id=f"chk_{key}")

            yield Label("Scope  -D / -T / -C")
            with Horizontal(classes="row"):
                yield Input(placeholder="db", id="db")
                yield Input(placeholder="table", id="tbl")
                yield Input(placeholder="col", id="col")

            yield Label("Proxy (optional)")
            yield Input(placeholder="http://127.0.0.1:8080", id="proxy")
            yield Label("Extra raw options (any sqlmap flag)")
            yield Input(placeholder="--tamper=space2comment --random-agent",
                        id="extra")

        with Vertical(id="main"):
            yield Static("", id="cmdline")
            yield Input(placeholder="full sqlmap command — edit freely, then Run",
                        id="cmd_edit")
            yield RichLog(id="log", highlight=True, markup=True, wrap=True,
                          auto_scroll=True)
            yield Static("", id="status")
            with Horizontal(id="buttons"):
                yield Button("▶ Run  (Ctrl+R)", id="run", variant="primary")
                yield Button("■ Stop", id="stop", variant="error", disabled=True)
                yield Button("✏ Edit command", id="edit_cmd")
                yield Button("Copy output", id="copy")
                yield Button("Save output", id="save")
                yield Button("Clear", id="clear")
                yield Button("sqlmap options", id="help")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "sqlmap UI"
        self.sub_title = "authorized testing only"
        self._load_config()
        log = self.query_one("#log", RichLog)
        if resolve_sqlmap_cmd():
            log.write("[dim]Pick a [b]preset[/b] (or options), set a target, then "
                      "press [b]Ctrl+R[/b] to run.  Press [b]F1[/b] for every "
                      "sqlmap option.[/]")
        else:
            log.write(f"[red]sqlmap was not found[/] (SQLMAP_PATH={SQLMAP_PATH!r}). "
                      "Set the [b]SQLMAP_PATH[/b] environment variable to your "
                      "sqlmap binary and restart.")
            self.query_one("#run", Button).disabled = True
        self.query_one("#cmd_edit", Input).display = False
        self.set_interval(0.5, self._tick)
        self._update_preview()
        self._update_status()

    # ----------------------------------------------------------- helpers
    def _get(self, wid: str) -> str:
        return self.query_one(f"#{wid}", Input).value.strip()

    def _checked(self, key: str) -> bool:
        return self.query_one(f"#chk_{key}", Checkbox).value

    # ----------------------------------------------------------- build argv
    @staticmethod
    def _write_request_file(text: str) -> str:
        normalised = text.replace("\r\n", "\n").replace("\n", "\r\n")
        fd, path = tempfile.mkstemp(prefix="sqlmapui_req_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(normalised)
        return path

    def _cleanup_request_file(self) -> None:
        if self._req_file:
            try:
                os.unlink(self._req_file)
            except OSError:
                pass
            self._req_file = None

    def _append_options(self, argv: list[str]) -> list[str]:
        """Add value flags, DBMS, action flags and extras. May raise ValueError."""
        for key, flag in VALUE_FLAGS.items():
            val = self._get(key)
            if not val:
                continue
            if any(c in val for c in "\n\r\x00"):
                raise ValueError(f"Invalid characters in field '{key}'.")
            if flag.startswith("--"):
                argv.append(f"{flag}={val}")
            else:
                argv += [flag, val]

        dbms = self.query_one("#dbms", Select).value
        if dbms and dbms != "auto-detect":
            argv.append(f"--dbms={dbms}")

        for key, flag in BOOL_FLAGS.items():
            if self._checked(key):
                argv.append(flag)

        extra = self._get("extra")
        if extra:
            try:
                argv += shlex.split(extra, posix=(os.name != "nt"))
            except ValueError as exc:
                raise ValueError(f"Could not parse extra options: {exc}")

        argv.append("--batch")  # never block on interactive prompts
        return argv

    def _target_args(self, *, for_preview: bool) -> list[str]:
        """Return the target portion of the command (-r / -u). Raises on error."""
        raw_request = self.query_one("#request", TextArea).text.strip()
        req_path = self._get("req_path")
        if raw_request:
            if for_preview:
                return ["-r", "<pasted-request.txt>"]
            self._req_file = self._write_request_file(raw_request)
            return ["-r", self._req_file]
        if req_path:
            if not for_preview and not os.path.isfile(req_path):
                raise ValueError(f"Request file not found: {req_path}")
            return ["-r", req_path]
        url = self._get("url")
        if not url:
            raise ValueError("Provide a target URL, paste a request, "
                             "or give a request file path.")
        if any(c in url for c in "\n\r\x00"):
            raise ValueError("Invalid characters in URL.")
        return ["-u", url]

    def build_argv(self) -> list[str]:
        cmd = resolve_sqlmap_cmd()
        if cmd is None:
            raise RuntimeError("sqlmap executable not found.")
        argv = list(cmd)
        argv += self._target_args(for_preview=False)
        self._append_options(argv)
        return argv

    # ----------------------------------------------------------- live preview
    def _update_preview(self) -> None:
        if self.proc and self.proc.poll() is None:
            return  # don't clobber the real command while running
        cmd = resolve_sqlmap_cmd()
        base = list(cmd) if cmd else ["sqlmap"]
        try:
            argv = base + self._target_args(for_preview=True)
            self._append_options(argv)
            self._preview_cmd = " ".join(shlex.quote(a) for a in argv)
        except (ValueError, RuntimeError):
            self._preview_cmd = ""
        if self._custom_mode:
            return  # user is hand-editing; leave the command bar/field alone
        if self._preview_cmd:
            self.query_one("#cmdline", Static).update(f"[dim]$ {self._preview_cmd}[/]")
        else:
            self.query_one("#cmdline", Static).update(
                "[dim]$ (set a target to preview the sqlmap command)[/]")

    @on(Input.Changed)
    def _on_input(self) -> None:
        self._update_preview()

    @on(Checkbox.Changed)
    def _on_check(self) -> None:
        self._update_preview()

    @on(Select.Changed)
    def _on_select(self) -> None:
        self._update_preview()

    @on(TextArea.Changed)
    def _on_textarea(self) -> None:
        self._update_preview()

    # ----------------------------------------------------------- status bar
    def _update_status(self, extra: str = "") -> None:
        ready = bool(resolve_sqlmap_cmd())
        dot = "[green]● sqlmap ready[/]" if ready else "[red]● sqlmap not found[/]"
        self.query_one("#status", Static).update(f"{dot}   {extra}")

    def _tick(self) -> None:
        if self.proc and self.proc.poll() is None and self._scan_start:
            el = time.time() - self._scan_start
            self._update_status(f"[yellow]running {el:0.0f}s[/]  ·  Ctrl+S to stop")

    # ----------------------------------------------------------- run / output
    def _log(self, markup: str, plain: str | None = None) -> None:
        self.query_one("#log", RichLog).write(markup)
        self._raw_lines.append(plain if plain is not None else markup)

    def _custom_argv(self) -> list[str]:
        """Parse the hand-edited command box into an argv list."""
        raw = self.query_one("#cmd_edit", Input).value.strip()
        if not raw:
            raise ValueError("The command box is empty.")
        try:
            argv = shlex.split(raw, posix=(os.name != "nt"))
        except ValueError as exc:
            raise ValueError(f"Could not parse the command: {exc}")
        if not argv:
            raise ValueError("The command box is empty.")
        # If the command still has the pasted-request placeholder, materialise
        # the pasted request into a real temp file and substitute it in.
        if "<pasted-request.txt>" in argv:
            req = self.query_one("#request", TextArea).text.strip()
            if not req:
                raise ValueError("Command references <pasted-request.txt> but "
                                 "the request box is empty.")
            self._req_file = self._write_request_file(req)
            argv = [self._req_file if a == "<pasted-request.txt>" else a
                    for a in argv]
        return argv

    def action_edit_command(self) -> None:
        """Toggle hand-editing of the full sqlmap command."""
        box = self.query_one("#cmd_edit", Input)
        btn = self.query_one("#edit_cmd", Button)
        if not self._custom_mode:
            self._custom_mode = True
            # Seed the editable box with the command the form would run.
            box.value = self._preview_cmd or (
                " ".join(resolve_sqlmap_cmd() or ["sqlmap"]) + " -u  --batch")
            box.display = True
            box.focus()
            btn.label = "✖ Use form"
            self.query_one("#cmdline", Static).update(
                "[yellow]✏ custom command mode — the box below runs as-is.[/]")
            self._log("[magenta]Custom command mode on.[/] Edit the command box "
                      "and press Ctrl+R. Click '✖ Use form' to go back.", None)
        else:
            self._custom_mode = False
            box.display = False
            btn.label = "✏ Edit command"
            self._update_preview()
            self._log("[magenta]Back to form mode.[/]", None)

    def action_run(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        try:
            argv = self._custom_argv() if self._custom_mode else self.build_argv()
        except (ValueError, RuntimeError) as exc:
            self._cleanup_request_file()
            self._log(f"[red][b]Error:[/b] {exc}[/]", f"Error: {exc}")
            if not self._custom_mode and ("URL" in str(exc) or "target" in str(exc)):
                self.query_one("#url", Input).focus()
            return

        reason = destructive_reason(argv)
        if reason:
            self._cleanup_request_file()
            self._log(f"[red][b]Blocked:[/b] {reason}.[/] This tool refuses "
                      "actions that can delete data. Remove it and try again.",
                      f"Blocked: {reason}.")
            return

        self._save_config()
        shown = " ".join(shlex.quote(a) for a in argv)
        self.query_one("#cmdline", Static).update(f"[dim]$ {shown}[/]")
        self._log(f"\n[cyan]▶ launching:[/] {shown}\n", f"$ {shown}")
        self.query_one("#run", Button).disabled = True
        self.query_one("#stop", Button).disabled = False
        self._stop = False
        self._scan_start = time.time()
        self.run_sqlmap(argv)

    @work(thread=True, exclusive=True)
    def run_sqlmap(self, argv: list[str]) -> None:
        try:
            kwargs = dict(
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, bufsize=1, universal_newlines=True,
            )
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True
            self.proc = subprocess.Popen(argv, **kwargs)
        except FileNotFoundError:
            self.call_from_thread(self._log,
                                  "[red]Could not launch sqlmap executable.[/]",
                                  "Could not launch sqlmap executable.")
            self.call_from_thread(self._scan_finished, None)
            return

        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            self.call_from_thread(self._write_line, raw.rstrip("\n"))
        self.proc.wait()
        self.call_from_thread(self._scan_finished, self.proc.returncode)

    def _write_line(self, line: str) -> None:
        self.query_one("#log", RichLog).write(colorize(line))
        self._raw_lines.append(line)

    def _scan_finished(self, code: int | None) -> None:
        el = time.time() - self._scan_start if self._scan_start else 0
        if self._stop:
            self._log("[yellow]■ scan stopped by user.[/]", "■ scan stopped by user.")
            self._update_status(f"[yellow]stopped[/] after {el:0.0f}s")
        elif code == 0:
            self._log(f"[green]■ done in {el:0.0f}s (exit 0).[/]",
                      f"■ done in {el:0.0f}s (exit 0).")
            self._update_status(f"[green]done[/] in {el:0.0f}s")
        else:
            self._log(f"[yellow]■ exited with code {code} after {el:0.0f}s.[/]",
                      f"■ exited with code {code} after {el:0.0f}s.")
            self._update_status(f"[yellow]exit {code}[/] after {el:0.0f}s")
        self.query_one("#run", Button).disabled = not bool(resolve_sqlmap_cmd())
        self.query_one("#stop", Button).disabled = True
        self.proc = None
        self._scan_start = None
        self._cleanup_request_file()

    def action_stop(self) -> None:
        if not (self.proc and self.proc.poll() is None):
            return
        self._stop = True
        try:
            if os.name == "nt":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                self.proc.terminate()
            except Exception:
                pass

    def action_clear(self) -> None:
        self.query_one("#log", RichLog).clear()
        self._raw_lines.clear()

    # ----------------------------------------------------------- clipboard
    def action_paste_clipboard(self) -> None:
        """Paste the clipboard into whichever field has focus.

        Works for any text Input (Target URL, Cookie, Proxy, …) and the raw
        request box. Bypasses terminal paste, so it works even where the
        terminal's own Ctrl+V doesn't reach the app.
        """
        text = read_clipboard()
        if not text:
            self._log("[red]Couldn't read the clipboard.[/] Copy the text again, "
                      "then click into a field and press Ctrl+B.", None)
            return
        focused = self.focused

        if isinstance(focused, TextArea):
            focused.insert(text)
            where = "request box"
        elif isinstance(focused, Input):
            # Single-line field: collapse any newlines so the value stays valid.
            focused.insert_text_at_cursor(" ".join(text.split()))
            where = f"{focused.id or 'input'} field"
        else:
            # Nothing focused (e.g. the paste button was clicked): default to
            # the request box, which is the common case for pasting.
            ta = self.query_one("#request", TextArea)
            ta.text = text.rstrip("\r\n")
            self.query_one("#req_box", Collapsible).collapsed = False
            ta.focus()
            where = "request box"

        self._update_preview()
        self._log(f"[green]Pasted {len(text.strip())} characters into the "
                  f"{where}.[/]", None)

    def action_copy_output(self) -> None:
        text = "\n".join(self._raw_lines)
        if not text.strip():
            self._log("[yellow]Nothing to copy yet.[/]", None)
            return
        if write_clipboard(text):
            self._log("[green]Output copied to clipboard.[/]", None)
        else:
            self._log("[red]Couldn't access the clipboard — use "
                      "'Save output' instead.[/]", None)

    def action_save_output(self) -> None:
        text = "\n".join(self._raw_lines)
        if not text.strip():
            self._log("[yellow]Nothing to save yet.[/]", None)
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path.cwd() / f"sqlmap-ui_{stamp}.log"
        try:
            path.write_text(text + "\n", encoding="utf-8")
            self._log(f"[green]Output saved to[/] {path}", None)
        except OSError as exc:
            self._log(f"[red]Couldn't save output: {exc}[/]", None)

    # ----------------------------------------------------------- help / presets
    def action_help(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        cmd = resolve_sqlmap_cmd()
        if cmd is None:
            self._log("[red]sqlmap not found.[/]", None)
            return
        self._log("\n[cyan]▶ sqlmap -hh (full option list)[/]\n", None)
        self.query_one("#run", Button).disabled = True
        self.query_one("#stop", Button).disabled = False
        self._stop = False
        self._scan_start = time.time()
        self.run_sqlmap(list(cmd) + ["-hh"])

    def apply_preset(self, name: str) -> None:
        p = PRESETS[name]
        for key in BOOL_FLAGS:
            self.query_one(f"#chk_{key}", Checkbox).value = key in p["checks"]
        self.query_one("#level", Input).value = p["level"]
        self.query_one("#risk", Input).value = p["risk"]
        self._update_preview()
        if self._custom_mode:  # keep the editable command box in sync
            self.query_one("#cmd_edit", Input).value = self._preview_cmd
        self._log(f"[magenta]Preset '{name}':[/] {p['desc']}", None)

    # ----------------------------------------------------------- config I/O
    def _load_config(self) -> None:
        try:
            data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for key in SAVED_INPUTS:
            if key in data:
                try:
                    self.query_one(f"#{key}", Input).value = str(data[key])
                except Exception:
                    pass
        if "dbms" in data:
            try:
                self.query_one("#dbms", Select).value = data["dbms"]
            except Exception:
                pass
        for key in BOOL_FLAGS:
            if key in data.get("checks", {}):
                try:
                    self.query_one(f"#chk_{key}", Checkbox).value = bool(
                        data["checks"][key])
                except Exception:
                    pass

    def _save_config(self) -> None:
        data = {key: self._get(key) for key in SAVED_INPUTS}
        data["dbms"] = self.query_one("#dbms", Select).value
        data["checks"] = {key: self._checked(key) for key in BOOL_FLAGS}
        try:
            CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError:
            pass

    def action_quit(self) -> None:
        self._save_config()
        self.exit()

    # ----------------------------------------------------------- button wiring
    @on(Button.Pressed, "#run")
    def _b_run(self) -> None: self.action_run()

    @on(Button.Pressed, "#stop")
    def _b_stop(self) -> None: self.action_stop()

    @on(Button.Pressed, "#clear")
    def _b_clear(self) -> None: self.action_clear()

    @on(Button.Pressed, "#copy")
    def _b_copy(self) -> None: self.action_copy_output()

    @on(Button.Pressed, "#save")
    def _b_save(self) -> None: self.action_save_output()

    @on(Button.Pressed, "#help")
    def _b_help(self) -> None: self.action_help()

    @on(Button.Pressed, "#paste_clip")
    def _b_paste(self) -> None: self.action_paste_clipboard()

    @on(Button.Pressed, "#edit_cmd")
    def _b_edit(self) -> None: self.action_edit_command()

    @on(Button.Pressed, "#p_quick")
    def _b_p_quick(self) -> None: self.apply_preset("quick")

    @on(Button.Pressed, "#p_standard")
    def _b_p_standard(self) -> None: self.apply_preset("standard")

    @on(Button.Pressed, "#p_enumerate")
    def _b_p_enum(self) -> None: self.apply_preset("enumerate")

    @on(Button.Pressed, "#p_full")
    def _b_p_full(self) -> None: self.apply_preset("full")


def colorize(line: str) -> str:
    """Add Rich markup based on sqlmap's own log-level tags."""
    from rich.markup import escape
    safe = escape(line)
    low = line.lower()
    if "[critical]" in low or "[error]" in low:
        return f"[red]{safe}[/]"
    if "[warning]" in low:
        return f"[yellow]{safe}[/]"
    if "[info]" in low:
        return f"[cyan]{safe}[/]"
    if ("is vulnerable" in low or "available databases" in low
            or "the back-end dbms is" in low):
        return f"[bold green]{safe}[/]"
    return safe


def main() -> None:
    SqlmapUI().run()


if __name__ == "__main__":
    main()
