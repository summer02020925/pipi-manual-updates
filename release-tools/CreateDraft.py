"""Strict data-only checks for creating one empty draft. No network or secrets."""
import json
import os
from pathlib import Path
import re
import sys
REPO='summer02020925/pipi-manual-updates'
def require(ok):
    if not ok: raise ValueError('Draft verification failed')
def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result);result[key]=value
    return result
def read(path,limit=65536):
    p=Path(path);require(not p.is_symlink() and p.is_file() and 0<p.stat().st_size<=limit)
    return json.loads(p.read_bytes(),object_pairs_hook=unique)
def version(text):
    require(isinstance(text,str) and re.fullmatch(r'(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}',text))
    parts=tuple(map(int,text.split('.')));require(all(p<=65535 for p in parts));return parts
def request(data,env):
    require(env.get('GITHUB_REPOSITORY')==REPO and env.get('GITHUB_REF')=='refs/heads/main' and env.get('GITHUB_EVENT_NAME')=='push')
    sha=env.get('GITHUB_SHA','');require(re.fullmatch('[0-9a-f]{40}',sha))
    require(isinstance(data,dict) and set(data)=={'schema','nonce','version'})
    require(type(data['schema']) is int and data['schema']==1)
    require(isinstance(data['nonce'],str) and re.fullmatch('[0-9a-f]{32}',data['nonce']))
    version(data['version']);return data['version'],sha
def page(data):
    require(isinstance(data,list) and len(data)<=10 and all(isinstance(x,dict) for x in data));return len(data)
def inventory(pages,v,expected_id=None):
    require(1<=len(pages)<=20 and all(page(p)==10 for p in pages[:-1]) and page(pages[-1])<10)
    seen=set();matches=[]
    for p in pages:
        for item in p:
            ident=item.get('id');require(type(ident) is int and ident>0 and ident not in seen);seen.add(ident)
            tag=item.get('tag_name');require(isinstance(tag,str))
            require(type(item.get('draft')) is bool and type(item.get('prerelease')) is bool)
            if tag=='v'+v:matches.append(item)
            if item.get('draft') is False and item.get('prerelease') is False:
                require(tag.startswith('v'));require(version(tag[1:])<version(v))
    if expected_id is None:require(not matches)
    else:require(len(matches)==1 and matches[0].get('id')==int(expected_id) and matches[0].get('draft') is True)
def tag_absent(path):
    # Exact-ref GET, not prefix matching/pagination. Fail closed on any tag,
    # including one created concurrently after preflight. Never alter the ref.
    p=Path(path);require(not p.is_symlink() and p.is_file() and 0<p.stat().st_size<=65536)
    raw=p.read_bytes();parts=re.split(br'\r?\n\r?\n',raw,maxsplit=1)
    require(len(parts)==2)
    status=re.fullmatch(br'HTTP/[^ ]+ ([0-9]{3})(?: [^\r\n]*)?',parts[0].splitlines()[0])
    require(status is not None and status.group(1)==b'404')
    body=json.loads(parts[1],object_pairs_hook=unique)
    require(isinstance(body,dict) and body.get('message')=='Not Found')
def payload(v,sha):
    version(v);require(re.fullmatch('[0-9a-f]{40}',sha))
    return dict(tag_name='v'+v,target_commitish=sha,name='v'+v,body='Empty reviewed release draft; no package or signature published.',draft=True,prerelease=False,make_latest='false',generate_release_notes=False)
def created(data,v,sha,expected=None):
    require(isinstance(data,dict) and type(data.get('id')) is int and data['id']>0)
    require(data.get('draft') is True and data.get('prerelease') is False and data.get('tag_name')=='v'+v)
    require(data.get('target_commitish')==sha and data.get('published_at') is None and data.get('assets')==[])
    if expected is not None:require(str(data['id'])==expected)
    return str(data['id'])
def main():
    mode=sys.argv[1];env=os.environ
    require(not Path('release-control').is_symlink())
    v,sha=request(read('release-control/create-draft.json',4096),env)
    if mode=='request':
        with open(env['GITHUB_ENV'],'a',encoding='utf-8') as f:f.write('DRAFT_VERSION='+v+'\n')
    elif mode=='page':print(page(read(sys.argv[2],1048576)))
    elif mode=='inventory':inventory([read(p,1048576) for p in sys.argv[2:]],v)
    elif mode=='after-inventory':
        require(re.fullmatch('[1-9][0-9]*',sys.argv[2]));inventory([read(p,1048576) for p in sys.argv[3:]],v,sys.argv[2])
    elif mode=='tag-absent':tag_absent(sys.argv[2])
    elif mode=='main':
        d=read(sys.argv[2]);require(isinstance(d,dict) and d.get('ref')=='refs/heads/main' and d.get('object',{}).get('sha')==sha)
    elif mode=='payload':Path(sys.argv[2]).write_text(json.dumps(payload(v,sha)),encoding='utf-8')
    elif mode=='created':print(created(read(sys.argv[2]),v,sha,sys.argv[3] if len(sys.argv)==4 else None))
    else:require(False)
if __name__=='__main__':
    try:main()
    except Exception:
        print('Draft creation checks failed. Do not retry blindly: inspect whether the draft already exists. No publication or overwrite is performed.',file=sys.stderr);sys.exit(1)
