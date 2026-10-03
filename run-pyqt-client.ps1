$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $root ".venv\Scripts\python.exe") (Join-Path $root "examples\pyqt_client.py")
