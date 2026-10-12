# -*- mode: python ; coding: utf-8 -*-
"""One file named NetScaler Health Check.exe for another Windows PC."""

from pathlib import Path

root = Path(SPECPATH)

a = Analysis(
    [str(root / "nshc_launch.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[(str(root / "nshc" / "data" / "checks.json"), "nshc/data")],
    hiddenimports=["nshc", "nshc.cli", "nshc.gui", "nshc.crypto", "nshc.catalog", "nshc.advisories"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NetScaler Health Check",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
