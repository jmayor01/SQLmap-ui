@echo off
REM Convenience launcher for Windows: installs deps on first run, then starts the UI.
cd /d "%~dp0"
python -c "import textual" 2>NUL || pip install -r requirements.txt
python sqlmap_ui.py %*
