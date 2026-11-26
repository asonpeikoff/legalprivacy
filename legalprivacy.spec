# legalprivacy.spec — PyInstaller build spec for legalPrivacy
# Produces a single-file executable: legalprivacy-launch (Linux/macOS) or legalprivacy-launch.exe (Windows)
#
# Build locally:
#   pip install pyinstaller
#   pyinstaller legalprivacy.spec
#
# Output: dist/legalprivacy-launch  (or dist/legalprivacy-launch.exe on Windows)

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

pw_datas, pw_binaries, pw_hidden = collect_all('playwright')

from PyInstaller.utils.hooks import collect_submodules

block_cipher = None
all_legalprivacy = collect_submodules('legalprivacy')      # every module, however lazily imported

a = Analysis(
    ['legalprivacy_entry.py'],
    pathex=['.'],
    binaries=pw_binaries,
    datas=[
        ('data', 'data'),               # bridges, example configs
        ('profiles', 'profiles'),       # optional — omit if dir absent
        ('legalprivacy/web', 'legalprivacy/web'),   # dashboard UI
    ] + pw_datas + [
    ],
    hiddenimports=[
        'legalprivacy.cli',
        'legalprivacy.controller',
        'legalprivacy.browser',
        'legalprivacy.domains',
        'legalprivacy.feeds',
        'legalprivacy.humanize',
        'legalprivacy.queries',
        'legalprivacy.safety',
        'legalprivacy.events',
        'legalprivacy.onion',
        'legalprivacy.observe',
        'psutil',
        'legalprivacy.paths',
        'legalprivacy.torcontrol',
        'legalprivacy.tormanager',
        'legalprivacy.webui',
        'legalprivacy.config',
        'legalprivacy.engines',
        'legalprivacy.identity',
        'legalprivacy.pacing',
        'legalprivacy.relay',
        'legalprivacy.scheduler',
        'legalprivacy.transports',
        'yaml',
        'requests',
        'urllib3',
        'charset_normalizer',
        'idna',
        'certifi',
        'socks',
    ] + all_legalprivacy + pw_hidden,
    hookspath=[],
    hooksconfig={},
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
    name='legalprivacy-launch',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,           # keep a console: it shows the dashboard link and is how you quit
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
