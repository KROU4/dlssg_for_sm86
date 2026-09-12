param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not $SkipTests) {
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed. EXE was not rebuilt.' }
}
python -c "from pathlib import Path; from patcher_app.packages import create_bundled_payload; b=create_bundled_payload(Path.cwd(), Path('build/bundled-payload')); print(b.label, b.revision)"
if ($LASTEXITCODE -ne 0) { throw 'Bundled payload validation failed.' }
python -m PyInstaller --noconfirm --clean DLSSG-Patcher.spec
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }
Copy-Item -LiteralPath 'dist\DLSSG-Patcher.exe' -Destination 'DLSSG-Patcher.exe' -Force
python verify_patcher.py
if ($LASTEXITCODE -ne 0) { throw 'Distribution smoke test failed.' }
Get-FileHash -LiteralPath 'DLSSG-Patcher.exe' -Algorithm SHA256
