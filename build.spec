# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Bastion — builds a single-file, UAC-elevated exe.

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = []
hiddenimports += collect_submodules('reportlab')
hiddenimports += [
    'checks.runner',
    'checks.system',
    'checks.firewall',
    'checks.defender',
    'checks.accounts',
    'checks.credentials',
    'checks.policies',
    'checks.encryption',
    'checks.updates',
    'checks.network',
    'checks.protocols',
    'checks.shares',
    'checks.services',
    'checks.software',
    'checks.mitigations',
    'checks.event_logging',
    'checks.feeds',
]

a = Analysis(
    ['bastion.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'PIL.ImageTk', 'pytest'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Bastion',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    manifest=None,
    icon=None,
)
