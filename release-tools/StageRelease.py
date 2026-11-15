"""Validate reviewed binary staging data. Does not fetch, sign, execute, or publish."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

MAX_PACKAGE = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
REPO = 'summer02020925/pipi-manual-updates'
FILES = {'PipiManual.exe', 'Microsoft.Web.WebView2.Core.dll',
         'Microsoft.Web.WebView2.WinForms.dll', 'WebView2Loader.dll',
         'PipiManual.exe.config', 'WebView2-LICENSE.txt', 'WebView2-NOTICE.txt'}

def require(ok):
    if not ok:
        raise ValueError('Staging verification rejected')

def inputs(env):
    version = env.get('VERSION', '')
    require(re.fullmatch(r'(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}', version))
    commit, blob, digest = (env.get(k, '') for k in ('STAGING_COMMIT', 'BLOB_SHA', 'PACKAGE_SHA256'))
    require(re.fullmatch(r'[0-9a-f]{40}', commit))
    require(re.fullmatch(r'[0-9a-f]{40}', blob))
    require(re.fullmatch(r'[0-9a-f]{64}', digest))
    text = env.get('PACKAGE_SIZE', '')
    require(re.fullmatch(r'[1-9][0-9]{0,7}', text))
    size = int(text)
    require(0 < size <= MAX_PACKAGE)
    return {'version': version, 'commit': commit, 'blob': blob, 'digest': digest,
            'size': size, 'asset': f'PipiManualFresh-{version}-win-x64.zip'}

def read_json(path):
    data = Path(path).read_bytes()
    require(0 < len(data) <= 65536)
    return json.loads(data)

def commit_tree(data, cfg):
    require(isinstance(data, dict) and data.get('sha') == cfg['commit'])
    tree = data.get('tree', {}).get('sha', '')
    require(isinstance(tree, str) and re.fullmatch(r'[0-9a-f]{40}', tree))
    return tree

def validate_tree(data, cfg):
    require(isinstance(data, dict) and data.get('truncated') is False)
    entries = data.get('tree')
    require(isinstance(entries, list) and len(entries) == 1)
    item = entries[0]
    require(isinstance(item, dict) and item.get('path') == cfg['asset'])
    require(item.get('type') == 'blob' and item.get('mode') == '100644')
    require(item.get('sha') == cfg['blob'] and type(item.get('size')) is int and item['size'] == cfg['size'])

def validate_package(path, cfg):
    p = Path(path)
    require(p.is_file() and p.stat().st_size == cfg['size'])
    digest, git = hashlib.sha256(), hashlib.sha1()
    git.update(b'blob ' + str(cfg['size']).encode('ascii') + b'\x00')
    with p.open('rb') as src:
        while True:
            block = src.read(65536)
            if not block:
                break
            digest.update(block); git.update(block)
    require(digest.hexdigest() == cfg['digest'] and git.hexdigest() == cfg['blob'])
    with zipfile.ZipFile(p) as archive:
        items = archive.infolist()
        require(len(items) == len(FILES) and {i.filename for i in items} == FILES)
        total = 0
        for item in items:
            require(not item.is_dir() and not (item.flag_bits & 1))
            kind = stat.S_IFMT(item.external_attr >> 16)
            require(kind in (0, stat.S_IFREG) and not (item.external_attr & 0x400))
            require(0 <= item.file_size <= MAX_EXPANDED)
            total += item.file_size
        require(total <= MAX_EXPANDED)
    # The existing signer subsequently performs the full independent ZIP/PE/key/feed validation.

def validate_release(data, cfg):
    require(isinstance(data, dict) and data.get('draft') is True and data.get('tag_name') == 'v' + cfg['version'])
    assets = data.get('assets')
    require(isinstance(assets, list))
    match = [a for a in assets if isinstance(a, dict) and a.get('name') == cfg['asset']]
    require(len(match) <= 1)
    if match:
        require(type(match[0].get('size')) is int and match[0]['size'] == cfg['size'])
        require(type(match[0].get('id')) is int and match[0]['id'] > 0)
        return str(match[0]['id'])
    return 'absent'

def main():
    cfg = inputs(os.environ)
    mode = sys.argv[1]
    if mode == 'inputs':
        print(cfg['asset'])
    elif mode == 'commit':
        print(commit_tree(read_json(sys.argv[2]), cfg))
    elif mode == 'tree':
        validate_tree(read_json(sys.argv[2]), cfg)
    elif mode == 'package':
        validate_package(sys.argv[2], cfg)
    elif mode == 'release':
        print(validate_release(read_json(sys.argv[2]), cfg))
    else:
        require(False)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No raw server response, environment, URL or token in diagnostics.
        print('Reviewed staging validation failed; draft is not ready for publication.', file=sys.stderr)
        sys.exit(1)
