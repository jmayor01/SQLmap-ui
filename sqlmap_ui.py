#!/usr/bin/env python3
"""
sqlmap-ui — a terminal UI for driving a locally installed sqlmap.

A keyboard-friendly TUI (built with Textual) that builds sqlmap command lines
from a form, runs sqlmap as a subprocess, and streams its live output.

For authorized security testing only.

Run:        python sqlmap_ui.py
Configure:  set SQLMAP_PATH to your sqlmap binary if it isn't on PATH, e.g.
            SQLMAP_PATH=/usr/bin/sqlmap python sqlmap_ui.py   (macOS/Linux)
            set SQLMAP_PATH=C:\\sqlmap\\sqlmap.py && python sqlmap_ui.py  (Windows)
"""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import threading

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


def resolve_sqlmap_cmd() -> list[str] | None:
    """Return the sqlmap command as a token list, or None if not found."""
    parts = shlex.split(SQLMAP_PATH, posix=(os.name != "nt"))
    if not parts:
        return None
    if len(parts) > 1:  # e.g. "python /opt/sqlmap/sqlmap.py"
        return parts
    if shutil.which(parts[0]):
        return parts
    # Fall back to the literal string so the error message is useful.
    return None


# Boolean checkboxes -> sqlmap flags
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

# Text inputs -> sqlmap flags
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
    "extra": None,  # raw, shlex-split
}


class SqlmapUI(App):
    CSS = """
    Screen { layout: horizontal; }

    #sidebar {
        width: 46;
        border-right: solid $primary;
        padding: 1 2;
    }
    #sidebar Label { color: $text-muted; margin-top: 1; }
    #sidebar Input, #sidebar Select { margin-bottom: 0; }
    .row { height: auto; }
    .row Input { width: 1fr; margin-right: 1; }
    #actions Static { color: $text-muted; text-style: bold; margin-top: 1; }
    Checkbox { height: 1; border: none; padding: 0; }

    #main { width: 1fr; }
    #cmdline {
        height: auto; min-height: 1; padding: 0 1;
        background: $panel; color: $text-muted; border-bottom: solid $primary;
    }
    #log { padding: 0 1; }

    #buttons { height: auto; padding: 1 2; align: left middle; }
    #buttons Button { margin-right: 2; }
    #status { height: auto; padding: 0 2; }
    .ok { color: $success; }
    .bad { color: $error; }
    """

    BINDINGS = [
        ("ctrl+r", "run", "Run scan"),
        ("ctrl+s", "stop", "Stop"),
        ("ctrl+l", "clear", "Clear log"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.proc: subprocess.Popen | None = None
        self._stop = False
        self._req_file: str | None = None

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
            yield Label("Extra raw options")
            yield Input(placeholder="--tamper=space2comment --random-agent", id="extra")

        with Vertical(id="main"):
            yield Static("", id="cmdline")
            yield RichLog(id="log", highlight=True, markup=True, wrap=True, auto_scroll=True)
            yield Static("", id="status")
            with Horizontal(id="buttons"):
                yield Button("Run scan", id="run", variant="primary")
                yield Button("Stop", id="stop", variant="error", disabled=True)
                yield Button("Clear", id="clear")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "sqlmap UI"
        self.sub_title = "authorized testing only"
        log = self.query_one("#log", RichLog)
        cmd = resolve_sqlmap_cmd()
        if cmd:
            self.query_one("#status", Static).update(
                f"[green]● sqlmap ready[/]  ({' '.join(cmd)})")
            log.write("[dim]Fill in a target, pick actions, then press "
                      "[b]Ctrl+R[/b] to run.[/]")
        else:
            self.query_one("#status", Static).update(
                f"[red]● sqlmap not found[/]  (SQLMAP_PATH={SQLMAP_PATH!r})")
            log.write("[red]sqlmap was not found.[/] Set the [b]SQLMAP_PATH[/b] "
                      "environment variable to your sqlmap binary and restart.")
            self.query_one("#run", Button).disabled = True

    # ----------------------------------------------------------- build argv
    def _get(self, wid: str) -> str:
        return self.query_one(f"#{wid}", Input).value.strip()

    @staticmethod
    def _write_request_file(text: str) -> str:
        # Normalise to CRLF line endings, which is what raw HTTP requests use
        # and what sqlmap's -r parser expects.
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

    def build_argv(self) -> list[str]:
        cmd = resolve_sqlmap_cmd()
        if cmd is None:
            raise RuntimeError("sqlmap executable not found.")

        argv = list(cmd)

        # A pasted raw HTTP request (-r) takes precedence over the URL field.
        raw_request = self.query_one("#request", TextArea).text.strip()
        if raw_request:
            self._req_file = self._write_request_file(raw_request)
            argv += ["-r", self._req_file]
        else:
            url = self._get("url")
            if not url:
                raise ValueError(
                    "Provide a target URL, or paste a raw HTTP request.")
            if any(c in url for c in "\n\r\x00"):
                raise ValueError("Invalid characters in URL.")
            argv += ["-u", url]

        for key, flag in VALUE_FLAGS.items():
            if key == "extra":
                continue
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
            if self.query_one(f"#chk_{key}", Checkbox).value:
                argv.append(flag)

        extra = self._get("extra")
        if extra:
            try:
                argv += shlex.split(extra, posix=(os.name != "nt"))
            except ValueError as exc:
                raise ValueError(f"Could not parse extra options: {exc}")

        argv.append("--batch")  # never block on interactive prompts
        return argv

    # --------------------------------------------------------------- actions
    def action_run(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        log = self.query_one("#log", RichLog)
        try:
            argv = self.build_argv()
        except (ValueError, RuntimeError) as exc:
            self._cleanup_request_file()
            log.write(f"[red][b]Error:[/b] {exc}[/]")
            return

        shown = " ".join(shlex.quote(a) for a in argv)
        self.query_one("#cmdline", Static).update(f"[dim]$ {shown}[/]")
        log.write(f"\n[cyan]▶ launching:[/] {shown}\n")

        self.query_one("#run", Button).disabled = True
        self.query_one("#stop", Button).disabled = False
        self._stop = False
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
            self.call_from_thread(self._write_line,
                                  "[red]Could not launch sqlmap executable.[/]")
            self.call_from_thread(self._scan_finished, None)
            return

        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            self.call_from_thread(self._write_line, raw.rstrip("\n"))
        self.proc.wait()
        self.call_from_thread(self._scan_finished, self.proc.returncode)

    def _write_line(self, line: str) -> None:
        self.query_one("#log", RichLog).write(colorize(line))

    def _scan_finished(self, code: int | None) -> None:
        log = self.query_one("#log", RichLog)
        if self._stop:
            log.write("[yellow]■ scan stopped by user.[/]")
        elif code == 0:
            log.write("[green]■ sqlmap finished (exit 0).[/]")
        else:
            log.write(f"[yellow]■ sqlmap exited with code {code}.[/]")
        self.query_one("#run", Button).disabled = not bool(resolve_sqlmap_cmd())
        self.query_one("#stop", Button).disabled = True
        self.proc = None
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

    # --------------------------------------------------------------- buttons
    @on(Button.Pressed, "#run")
    def _btn_run(self) -> None:
        self.action_run()

    @on(Button.Pressed, "#stop")
    def _btn_stop(self) -> None:
        self.action_stop()

    @on(Button.Pressed, "#clear")
    def _btn_clear(self) -> None:
        self.action_clear()


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
    if "is vulnerable" in low or "available databases" in low \
            or "the back-end dbms is" in low:
        return f"[bold green]{safe}[/]"
    return safe


def main() -> None:
    SqlmapUI().run()


if __name__ == "__main__":
    main()
