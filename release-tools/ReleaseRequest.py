"""Validate explicit release requests; never fetch, execute, sign or publish."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

MAX_PACKAGE = 32 * 1024 * 1024

def require(ok):
    if not ok: raise ValueError('Release request rejected')

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result

def validate(data, mode):
    require(mode in ('stage', 'publish') and isinstance(data, dict))
    fields = {'schema', 'nonce', 'version', 'package_sha256', 'package_size'}
    if mode == 'stage': fields |= {'staging_commit', 'blob_sha'}
    else: fields.add('release_id')
    require(set(data) == fields)
    require(type(data['schema']) is int and data['schema'] == 1)
    patterns = {'nonce': r'[0-9a-f]{32}', 'version': r'(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}',
                'package_sha256': r'[0-9a-f]{64}'}
    if mode == 'stage': patterns.update(staging_commit=r'[0-9a-f]{40}', blob_sha=r'[0-9a-f]{40}')
    for key, pattern in patterns.items():
        require(isinstance(data[key], str) and re.fullmatch(pattern, data[key]))
    require(all(int(part) <= 65535 for part in data['version'].split('.')))
    require(type(data['package_size']) is int and 0 < data['package_size'] <= MAX_PACKAGE)
    if mode == 'publish': require(type(data['release_id']) is int and 0 < data['release_id'] <= 9007199254740991)
    return {key.upper(): str(value) for key, value in data.items() if key not in ('schema', 'nonce')}

def load(mode, env):
    require(env.get('GITHUB_REPOSITORY') == 'summer02020925/pipi-manual-updates')
    require(env.get('GITHUB_REF') == 'refs/heads/main')
    if env.get('GITHUB_EVENT_NAME') == 'push':
        parent = Path('release-control'); path = parent / (mode + '.json')
        require(not parent.is_symlink() and not path.is_symlink() and path.is_file())
        require(0 < path.stat().st_size <= 4096)
        data = json.loads(path.read_bytes(), object_pairs_hook=unique)
    else:
        require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch')
        keys = ['version','package_sha256','package_size']
        if mode == 'stage': keys += ['staging_commit','blob_sha']
        data = {key:env.get('RAW_'+key.upper(), '') for key in keys}
        require(re.fullmatch(r'[1-9][0-9]{0,7}', data['package_size']))
        data['package_size'] = int(data['package_size'])
        if mode == 'publish':
            text=env.get('RAW_RELEASE_ID','');require(re.fullmatch(r'[1-9][0-9]{0,15}',text));data['release_id']=int(text)
        data.update(schema=1, nonce='0'*32)
    return validate(data, mode)

def package(path, env):
    # Same exact reviewed hash is checked before signing and after re-download.
    digest, size = env.get('PACKAGE_SHA256',''), env.get('PACKAGE_SIZE','')
    require(re.fullmatch(r'[0-9a-f]{64}',digest) and re.fullmatch(r'[1-9][0-9]{0,7}',size))
    size = int(size);require(0 < size <= MAX_PACKAGE)
    p=Path(path);require(not p.is_symlink() and p.is_file() and p.stat().st_size == size)
    h=hashlib.sha256()
    with p.open('rb') as src:
        while True:
            b=src.read(65536)
            if not b: break
            h.update(b)
    require(h.hexdigest() == digest)

if __name__ == '__main__':
    try:
        if sys.argv[1] == 'package': package(sys.argv[2],os.environ)
        else:
            values=load(sys.argv[1],os.environ)
            with open(os.environ['GITHUB_ENV'],'a',encoding='utf-8') as output:
                for key,value in values.items(): output.write(key+'='+value+'\n')
    except Exception:
        print('Release request or reviewed package verification failed; no approval inferred.',file=sys.stderr)
        sys.exit(1)
