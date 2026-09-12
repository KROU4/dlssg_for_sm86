# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

root = Path(SPECPATH)
a = Analysis(
    [str(root / 'patcher.py')],
    pathex=[str(root)],
    binaries=[],
    # Add payload AFTER dependency analysis: PyInstaller otherwise reclassifies
    # the proxy DLLs as BINARY and can copy dxgi.dll into the application's root.
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['PyQt6', 'PyQt5', 'PySide2', 'tkinter', 'numpy', 'pandas', 'matplotlib', 'torch'],
    noarchive=False,
)
payload = root / 'build' / 'bundled-payload'
for name, source, kind in a.binaries:
    if Path(source).resolve().is_relative_to(root.resolve()) and Path(source).suffix.lower() == '.dll':
        raise RuntimeError(f'Project proxy must never become an application dependency: {source}')
a.datas += [(f'payload/{file.name}', str(file), 'DATA') for file in payload.iterdir() if file.is_file()]
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='DLSSG-Patcher',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
)
