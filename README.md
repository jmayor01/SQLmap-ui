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

## Install & run (Windows)

```cmd
pip install -r requirements.txt
python sqlmap_ui.py
```

Or just double-click / run **`run.bat`**, which installs the dependency on first
launch and starts the UI.

If `sqlmap` is on your `PATH`, the UI finds it automatically. Otherwise point it
at your install with the `SQLMAP_PATH` environment variable:

```cmd
:: if you installed sqlmap from source (sqlmap.py)
set SQLMAP_PATH=python C:\tools\sqlmap\sqlmap.py
python sqlmap_ui.py

:: if you installed sqlmap via pip (sqlmap.exe on PATH) nothing extra is needed
```

> Tip: run it in **Windows Terminal** or PowerShell for the best colors; the
> classic `cmd.exe` console works too.

### Linux / macOS

```bash
pip install -r requirements.txt
python3 sqlmap_ui.py          # or: ./run.sh
SQLMAP_PATH="python /opt/sqlmap/sqlmap.py" python3 sqlmap_ui.py
```

## Using it

1. Enter the **target URL** (e.g. `http://host/page.php?id=1`) **— or** expand
   **"Paste raw HTTP request (-r)"** and paste a full request copied from Burp,
   ZAP, or your browser's dev tools. When a request is pasted it takes
   precedence over the URL field; mark the injection point with `*` if you want
   to target a specific parameter.
2. Optionally set POST data, a cookie, level/risk, threads, or a DBMS.
3. Tick the **actions** you want (enumerate databases, dump tables, etc.).
4. Press **Ctrl+R** (or click **Run scan**).

The pasted request is saved to a temporary file (with the CRLF line endings
sqlmap expects), passed as `-r`, and deleted automatically when the scan ends.

**Paste not working?** Terminal paste is finicky — especially in the legacy
`cmd.exe` console, which doesn't always hand pasted text to the app. Two
reliable fixes:

- Click the **📋 Paste from clipboard** button (or press **Ctrl+B**). This reads
  your clipboard directly (via PowerShell on Windows) and drops it into the
  request box, so it works no matter how your terminal handles `Ctrl+V`.
- Or save the request to a `.txt` file and use the **"…or load the request from
  a saved file"** field.

Running in **Windows Terminal** (not `cmd.exe`) also makes normal `Ctrl+V` /
right-click paste work.

## All sqlmap options

The form covers the common actions, but **any** sqlmap flag works — type it into
the **Extra raw options** box (e.g. `--tamper=space2comment --technique=BEUST
--flush-session`). Press **F1** (or the **sqlmap options** button) to print
sqlmap's complete option list (`sqlmap -hh`) into the output pane for reference.

Output streams in the right-hand pane as sqlmap runs. The exact command is shown
above the log so you can see — and learn — the flags being used.

### Keyboard shortcuts

| Key      | Action                         |
|----------|--------------------------------|
| `Ctrl+R` | Run scan                       |
| `Ctrl+S` | Stop scan                      |
| `Ctrl+B` | Paste request from clipboard   |
| `Ctrl+L` | Clear log                      |
| `F1`     | Show all sqlmap options (`-hh`)|
| `Ctrl+Q` | Quit                           |

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
