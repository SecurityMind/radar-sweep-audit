"""Repository-scoped, event-only public witness. Never reads private user data."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import math
import os
import re
import subprocess
import time
from urllib.request import Request, urlopen

REPO='SecurityMind/radar-sweep-audit'
CAMPAIGN='radar-sweep-badge-20261109-v1'
CHAIN='52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971'
ROOT=Path(__file__).resolve().parents[1]
API='https://api.github.com/repos/'+REPO

def canonical(v):
    return json.dumps(v,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')

def instant(v):
    d=datetime.fromisoformat(v.replace('Z','+00:00'))
    if d.tzinfo is None:raise ValueError('time_requires_timezone')
    return d.astimezone(timezone.utc)

def validate_body(raw, *, now=None):
    if len(raw)>60000:raise ValueError('body_too_large')
    text=raw.decode('ascii');prefix,sha,manifest=text.split('\n',2)
    if prefix!='radar-sweep-seal-v1' or sha!='sha256:'+sha256(manifest.encode()).hexdigest():
        raise ValueError('seal_fingerprint_invalid')
    m=json.loads(manifest)
    expected={'protocol','campaign_id','rules_sha256','starts_at','closes_at','round','chain_hash','tickets','speed','tickets_sha256','speed_snapshot_sha256'}
    if set(m)!=expected or canonical(m)!=manifest.encode():raise ValueError('manifest_schema_invalid')
    rules_sha=(ROOT/'rules-sha256.txt').read_text().strip()
    if sha256((ROOT/'algorithm.json').read_bytes()).hexdigest()!=rules_sha:raise ValueError('rules_source_drift')
    if m['protocol']!='radar-sweep-v1' or m['campaign_id']!=CAMPAIGN or m['rules_sha256']!=rules_sha or m['chain_hash']!=CHAIN:
        raise ValueError('campaign_or_rules_invalid')
    close=instant(m['closes_at']).timestamp()
    if close-instant(m['starts_at']).timestamp()!=432000:raise ValueError('duration_invalid')
    rnd=math.ceil((close+600-1692803367)/3)+1
    if type(m['round'])is not int or m['round']!=rnd:raise ValueError('fixed_round_invalid')
    now=time.time() if now is None else now
    if not close<=now<1692803367+(rnd-1)*3:raise ValueError('publication_outside_committed_window')
    tickets=m['tickets']
    if not isinstance(tickets,list) or len(tickets)<2 or tickets!=sorted(set(tickets)) or not all(isinstance(t,str)and re.fullmatch('R[A-F0-9]{12}',t)for t in tickets):
        raise ValueError('anonymous_ticket_list_invalid')
    speed=m['speed']
    if speed.get('status')=='missing':
        if speed!={'status':'missing','tok_per_second':None,'source_at':None,'published_at':None}:raise ValueError('missing_speed_invalid')
    elif speed.get('status')=='available':
        if set(speed)!={'status','tok_per_second','source_at','published_at','frame_sha256'} or not isinstance(speed['tok_per_second'],str) or not re.fullmatch(r'(0|[1-9][0-9]*)(\.[0-9]+)?',speed['tok_per_second']) or not re.fullmatch('[a-f0-9]{64}',speed['frame_sha256']):
            raise ValueError('speed_schema_invalid')
        if not instant(speed['source_at'])<=instant(speed['published_at'])<instant(m['closes_at']):raise ValueError('late_speed_invalid')
    else:raise ValueError('speed_status_invalid')
    if m['tickets_sha256']!=sha256(canonical(tickets)).hexdigest() or m['speed_snapshot_sha256']!=sha256(canonical(speed)).hexdigest():
        raise ValueError('component_fingerprint_invalid')
    return m,text

def api(path, *, body=None):
    headers={'Accept':'application/vnd.github+json','User-Agent':'radar-sweep-public-witness-v1','X-GitHub-Api-Version':'2022-11-28','Authorization':'Bearer '+os.environ['GITHUB_TOKEN']}
    if body is not None:headers['Authorization']='Bearer '+os.environ['GITHUB_TOKEN'];headers['Content-Type']='application/json'
    request=Request(API+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
    with urlopen(request,timeout=25)as r:
        if r.geturl()!=API+path:raise ValueError('github_redirect_forbidden')
        return json.load(r)

def publish(request_path):
    request=json.loads((ROOT/request_path).read_bytes())
    if set(request)!={'mode','body_sha256','body_file'} or request['mode']not in ('seal','smoke'):
        raise ValueError('request_schema_invalid')
    source=request['body_file'];prefix='seals'if request['mode']=='seal'else'smoke'
    if not re.fullmatch(prefix+r'/[a-f0-9]{64}\.txt',source):raise ValueError('source_path_invalid')
    path=ROOT/source
    if path.is_symlink() or not path.is_file():raise ValueError('regular_source_required')
    raw=path.read_bytes()
    if sha256(raw).hexdigest()!=request['body_sha256']:raise ValueError('request_body_fingerprint_invalid')
    m,text=validate_body(raw)
    issue=1 if request['mode']=='seal'else 2
    if issue==1:
        url='https://api.codexradar.com/api/v1/community/sweep/manifest'
        with urlopen(Request(url,headers={'Cache-Control':'no-cache'}),timeout=25)as r:
            if r.geturl()!=url or 'no-store'not in r.headers.get('Cache-Control','') or r.read(65001)!=text.split('\n',2)[2].encode():
                raise ValueError('official_public_manifest_mismatch')
    # Public unauthenticated search; never create a second timestamp for a retry.
    for page in range(1,101):
        items=api(f'/issues/{issue}/comments?per_page=100&page={page}')
        for comment in items:
            if comment.get('body')==text and comment.get('user',{}).get('login')=='github-actions[bot]' and comment['created_at']==comment['updated_at']:
                print(json.dumps({'status':'already_public','issue':issue,'comment_id':comment['id'],'created_at':comment['created_at']}));return
        if len(items)<100:break
    remaining=math.ceil(instant(m['closes_at']).timestamp())-time.time()
    if remaining>0:time.sleep(min(remaining,1))
    validate_body(raw)
    comment=api(f'/issues/{issue}/comments',body={'body':text})
    if comment['body']!=text or comment['created_at']!=comment['updated_at']:
        raise ValueError('public_comment_mismatch')
    print(json.dumps({'status':'published','issue':issue,'comment_id':comment['id'],'created_at':comment['created_at'],'seal_sha256':text.split('\n',2)[1][7:]}))

def main():
    if os.environ.get('GITHUB_REPOSITORY')!=REPO:raise ValueError('repository_binding_required')
    revision=os.environ['GITHUB_SHA']
    if not re.fullmatch('[a-f0-9]{40}',revision):raise ValueError('revision_invalid')
    names=subprocess.check_output(['git','diff-tree','--no-commit-id','--name-only','-r',revision],cwd=ROOT,text=True).splitlines()
    requests=[n for n in names if re.fullmatch(r'requests/[a-f0-9]{32}\.json',n)]
    if len(requests)!=1:raise ValueError('exactly_one_publication_request_required')
    publish(requests[0])

if __name__=='__main__':main()
