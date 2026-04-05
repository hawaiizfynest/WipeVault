# WipeVault.spec — PyInstaller build specification
# Windows: python -m PyInstaller WipeVault.spec
# macOS:   python -m PyInstaller WipeVault.spec
# Linux:   python -m PyInstaller WipeVault.spec

import sys
import os

block_cipher = None

a = Analysis(
    ['src/wipevault.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PyQt6',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'reportlab',
        'reportlab.lib',
        'reportlab.platypus',
        'reportlab.lib.pagesizes',
        'reportlab.lib.colors',
        'reportlab.lib.units',
        'reportlab.lib.styles',
        'reportlab.lib.enums',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='WipeVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window on Windows
    icon=None,              # Add path to .ico/.icns here when ready
)

# macOS .app bundle
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='WipeVault.app',
        icon=None,
        bundle_identifier='com.wipevault.app',
        info_plist={
            'NSPrincipalClass': 'NSApplication',
            'NSHighResolutionCapable': True,
            'CFBundleShortVersionString': '1.0.0',
            'CFBundleVersion': '1.0.0',
            'NSHumanReadableCopyright': 'WipeVault',
        },
    )
