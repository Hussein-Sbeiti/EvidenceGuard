# Build on each target OS; PyInstaller is not a cross compiler.
from pathlib import Path
import sys
from PyInstaller.utils.hooks import collect_all

root = Path(SPECPATH).parent
datas = [(str(root / 'app' / 'static'), 'app/static'),
         (str(root / 'desktop' / 'release.json'), 'desktop')]
binaries = []
hidden = ['uvicorn.logging', 'uvicorn.loops.asyncio',
          'uvicorn.protocols.http.h11_impl', 'uvicorn.lifespan.on', 'certifi', 'zstandard']
for package in ('tree_sitter', 'tree_sitter_javascript', 'tree_sitter_typescript'):
    package_data, package_binaries, package_hidden = collect_all(package)
    datas += package_data
    binaries += package_binaries
    hidden += package_hidden
a = Analysis([str(root / 'run_scanner.py')], pathex=[str(root)], binaries=binaries,
             datas=datas, hiddenimports=hidden,
             excludes=['torch', 'transformers', 'peft', 'trl', 'pytest', 'IPython'],
             noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='VulnAI-Scanner',
          debug=False, strip=False, upx=False, console=sys.platform.startswith('linux'))
collection = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name='VulnAI-Scanner')
if sys.platform == 'darwin':
    app = BUNDLE(collection, name='VulnAI-Scanner.app', bundle_identifier='edu.csc733.vulnaiscanner')
