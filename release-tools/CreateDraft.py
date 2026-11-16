"""Strict data-only checks for creating one empty draft. No network or secrets."""
import json
import os
from pathlib import Path
import re
import sys
REPO='summer02020925/pipi-manual-updates'
CODES=frozenset({'unspecified','duplicate-json-key','file-bounds','version-format','version-range','page-shape','pagination-incomplete','release-id-format','duplicate-release-id','duplicate-release-conflict','release-tag-format','release-flags','version-floor','existing-target','target-not-unique','expected-id-mismatch','target-not-draft','expected-id-renamed','response-shape','target-tag-mismatch','target-commit-mismatch','unexpected-publication','unexpected-assets','tag-response-format','tag-not-404'})
class DraftCheckError(ValueError):
    def __init__(self,code):
        self.code=code if code in CODES else 'unspecified'
        super().__init__('Draft verification failed')
def require(ok,code='unspecified'):
    if not ok: raise DraftCheckError(code)
def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'duplicate-json-key');result[key]=value
    return result
def read(path,limit=65536):
    p=Path(path);require(not p.is_symlink() and p.is_file() and 0<p.stat().st_size<=limit,'file-bounds')
    return json.loads(p.read_bytes(),object_pairs_hook=unique)
def version(text):
    require(isinstance(text,str) and re.fullmatch(r'(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){3}',text),'version-format')
    parts=tuple(map(int,text.split('.')));require(all(p<=65535 for p in parts),'version-range');return parts
def request(data,env):
    require(env.get('GITHUB_REPOSITORY')==REPO and env.get('GITHUB_REF')=='refs/heads/main' and env.get('GITHUB_EVENT_NAME')=='push')
    sha=env.get('GITHUB_SHA','');require(re.fullmatch('[0-9a-f]{40}',sha))
    require(isinstance(data,dict) and set(data)=={'schema','nonce','version'})
    require(type(data['schema']) is int and data['schema']==1)
    require(isinstance(data['nonce'],str) and re.fullmatch('[0-9a-f]{32}',data['nonce']))
    version(data['version']);return data['version'],sha
def page(data):
    require(isinstance(data,list) and len(data)<=10 and all(isinstance(x,dict) for x in data),'page-shape');return len(data)
def inventory(pages,v,expected_id=None):
    require(1<=len(pages)<=20 and all(page(p)==10 for p in pages[:-1]) and page(pages[-1])<10,'pagination-incomplete')
    seen=set();matches=[]
    for p in pages:
        for item in p:
            ident=item.get('id');require(type(ident) is int and ident>0,'release-id-format');require(ident not in seen,'duplicate-release-id');seen.add(ident)
            tag=item.get('tag_name');require(isinstance(tag,str),'release-tag-format')
            require(type(item.get('draft')) is bool and type(item.get('prerelease')) is bool,'release-flags')
            if tag=='v'+v:matches.append(item)
            if item.get('draft') is False and item.get('prerelease') is False:
                require(tag.startswith('v'),'release-tag-format');require(version(tag[1:])<version(v),'version-floor')
    if expected_id is None:require(not matches,'existing-target')
    else:
        require(len(matches)==1,'target-not-unique');require(matches[0].get('id')==int(expected_id),'expected-id-mismatch');require(matches[0].get('draft') is True,'target-not-draft')
class RetryableVisibility(Exception):pass
class RetryableDuplicate(Exception):pass
def post_inventory(pages,v,sha,expected_id):
    # Retry only a complete list with byte-equivalent JSON objects for repeated IDs.
    # Validate every remaining predicate before classifying the duplicate as transient.
    require(1<=len(pages)<=20 and all(page(p)==10 for p in pages[:-1]) and page(pages[-1])<10,'pagination-incomplete')
    seen={};origins={};rows=[];duplicate=False
    for index,batch in enumerate(pages):
        local_seen=set()
        for item in batch:
            ident=item.get('id');require(type(ident) is int and ident>0,'release-id-format')
            require(ident not in local_seen,'duplicate-release-id');local_seen.add(ident)
            require(type(item.get('draft')) is bool and type(item.get('prerelease')) is bool,'release-flags')
            if ident in seen:
                require(origins[ident]!=index,'duplicate-release-id')
                require(json.dumps(item,sort_keys=True,allow_nan=False)==json.dumps(seen[ident],sort_keys=True,allow_nan=False),'duplicate-release-conflict');duplicate=True
            else:seen[ident]=item;origins[ident]=index;rows.append(item)
    if duplicate:
        normalized=[rows[i:i+10] for i in range(0,len(rows),10)]
        if not normalized or len(normalized[-1])==10:normalized.append([])
        try: _post_inventory_strict(normalized,v,sha,expected_id)
        except RetryableVisibility: pass # Missing exact ID/tag is independently retryable.
        raise RetryableDuplicate()
    _post_inventory_strict(pages,v,sha,expected_id)
def _post_inventory_strict(pages,v,sha,expected_id):
    # First validate pagination/types/uniqueness/version floor without weakening any guard.
    matches=[item for p in pages for item in p if isinstance(item,dict) and item.get('tag_name')=='v'+v]
    if not matches:
        inventory(pages,v) # An otherwise-valid complete list, lacking only this new draft.
        require(not any(item.get('id')==int(expected_id) for p in pages for item in p),'expected-id-renamed')
        raise RetryableVisibility()
    inventory(pages,v,expected_id)
    created(matches[0],v,sha,str(expected_id)) # Repeat full metadata check on list snapshot.
def tag_absent(path):
    # Exact-ref GET, not prefix matching/pagination. Fail closed on any tag,
    # including one created concurrently after preflight. Never alter the ref.
    p=Path(path);require(not p.is_symlink() and p.is_file() and 0<p.stat().st_size<=65536)
    raw=p.read_bytes();parts=re.split(br'\r?\n\r?\n',raw,maxsplit=1)
    require(len(parts)==2,'tag-response-format')
    status=re.fullmatch(br'HTTP/[^ ]+ ([0-9]{3})(?: [^\r\n]*)?',parts[0].splitlines()[0])
    require(status is not None,'tag-response-format');require(status.group(1)==b'404','tag-not-404')
    body=json.loads(parts[1],object_pairs_hook=unique)
    require(isinstance(body,dict) and body.get('message')=='Not Found')
def payload(v,sha):
    version(v);require(re.fullmatch('[0-9a-f]{40}',sha))
    return dict(tag_name='v'+v,target_commitish=sha,name='v'+v,body='Empty reviewed release draft; no package or signature published.',draft=True,prerelease=False,make_latest='false',generate_release_notes=False)
def created(data,v,sha,expected=None):
    require(isinstance(data,dict) and type(data.get('id')) is int and data['id']>0,'response-shape')
    require(data.get('draft') is True and data.get('prerelease') is False,'target-not-draft');require(data.get('tag_name')=='v'+v,'target-tag-mismatch')
    require(data.get('target_commitish')==sha,'target-commit-mismatch');require(data.get('published_at') is None,'unexpected-publication');require(data.get('assets')==[],'unexpected-assets')
    if expected is not None:require(str(data['id'])==expected,'expected-id-mismatch')
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
        require(re.fullmatch('[1-9][0-9]*',sys.argv[2]));post_inventory([read(p,1048576) for p in sys.argv[3:]],v,sha,sys.argv[2])
    elif mode=='tag-absent':tag_absent(sys.argv[2])
    elif mode=='main':
        d=read(sys.argv[2]);require(isinstance(d,dict) and d.get('ref')=='refs/heads/main' and d.get('object',{}).get('sha')==sha)
    elif mode=='payload':Path(sys.argv[2]).write_text(json.dumps(payload(v,sha)),encoding='utf-8')
    elif mode=='created':print(created(read(sys.argv[2]),v,sha,sys.argv[3] if len(sys.argv)==4 else None))
    else:require(False)
if __name__=='__main__':
    try:main()
    except RetryableDuplicate:
        print('Complete inventory contains consistent duplicate release IDs; bounded full read-only recheck required.',file=sys.stderr);sys.exit(75)
    except RetryableVisibility:
        print('New draft not yet visible in otherwise valid complete inventory; read-only verification may be retried within its bound.',file=sys.stderr);sys.exit(75)
    except DraftCheckError as error:
        print('Draft creation checks failed. code='+error.code+'. Inspect existing draft; no mutation is retried.',file=sys.stderr);sys.exit(1)
    except Exception:
        print('Draft creation checks failed. code=unexpected-runtime. Do not retry blindly: inspect whether the draft already exists. No publication or overwrite is performed.',file=sys.stderr);sys.exit(1)
