# sqlmap UI

A keyboard-friendly **terminal UI** for a locally installed
[sqlmap](https://sqlmap.org/). It builds sqlmap command lines from a simple
form, runs sqlmap for you, and streams its live, colorized output — no browser,
no web server. Runs in any terminal (or as a standalone `.exe`).

> ⚠️ **For authorized security testing only.** Only run sqlmap against systems
> you own or have explicit written permission to test.

![preview](preview.svg)

## Requirements

- Python 3.9+
- [sqlmap](https://github.com/sqlmapproject/sqlmap) installed (you already have it)
- `textual` (the only Python dependency)

## Install & run

```bash
pip install -r requirements.txt
python sqlmap_ui.py
```

If `sqlmap` is on your `PATH`, the UI finds it automatically. Otherwise point it
at your install with the `SQLMAP_PATH` environment variable:

```bash
# Linux / macOS
SQLMAP_PATH=/usr/bin/sqlmap python sqlmap_ui.py
SQLMAP_PATH="python /opt/sqlmap/sqlmap.py" python sqlmap_ui.py
```

```cmd
:: Windows
set SQLMAP_PATH=C:\tools\sqlmap\sqlmap.py
python sqlmap_ui.py
```

## Using it

1. Enter the **target URL** (e.g. `http://host/page.php?id=1`).
2. Optionally set POST data, a cookie, level/risk, threads, or a DBMS.
3. Tick the **actions** you want (enumerate databases, dump tables, etc.).
4. Press **Ctrl+R** (or click **Run scan**).

Output streams in the right-hand pane as sqlmap runs. The exact command is shown
above the log so you can see — and learn — the flags being used.

### Keyboard shortcuts

| Key      | Action      |
|----------|-------------|
| `Ctrl+R` | Run scan    |
| `Ctrl+S` | Stop scan   |
| `Ctrl+L` | Clear log   |
| `Ctrl+Q` | Quit        |

Anything the form doesn't cover can be typed into **Extra raw options** (e.g.
`--tamper=space2comment --random-agent`); it's passed straight to sqlmap.
`--batch` is always added so sqlmap never blocks waiting for input.

## Build a standalone .exe (Windows)

No Python needed on the target machine:

```cmd
pip install pyinstaller
pyinstaller --onefile --name sqlmap-ui sqlmap_ui.py
```

The binary lands in `dist/`. (sqlmap itself still needs to be installed; set
`SQLMAP_PATH` if it isn't on `PATH`.) The same command works on Linux/macOS to
produce a single-file binary.

## Notes on safety

- sqlmap is launched directly as a subprocess — **no shell is ever invoked**, so
  form values can't be used for shell injection.
- Stopping a scan terminates the whole sqlmap process group.
