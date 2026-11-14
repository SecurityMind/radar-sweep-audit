"""Run with Python 3 and py-ecc 8.0.0. All inputs are public."""
import json
from pathlib import Path
from datetime import datetime
from sweep_crypto import digest, canonical, draw_order, round_at, verify_beacon, CHAIN

HERE = Path(__file__).resolve().parent
def calculate():
    notice = json.loads((HERE/'announcement.json').read_bytes())
    assert notice['html_url'].endswith('#issuecomment-6879338768')
    assert notice['created_at'] == notice['updated_at'] == '2026-11-14T15:03:18Z'
    rnd = round_at(datetime.fromisoformat(notice['created_at'].replace('Z','+00:00')).timestamp() + 600)
    assert rnd == 33955278
    raw = (HERE/'manifest.json').read_bytes()
    seal = digest(raw)
    assert seal == '464e976cc9adea01387c46c9dd512481c5026d6e97c28d35f9114f45064e62f5' and seal in notice['body']
    manifest = json.loads(raw)
    tickets = manifest['tickets']
    assert manifest['chain_hash'] == CHAIN['hash']
    assert len(tickets) == 113 and tickets == sorted(set(tickets))
    assert digest(canonical(tickets)) == manifest['tickets_sha256']
    beacon = verify_beacon(json.loads((HERE/'beacon.json').read_bytes()), rnd)
    campaign = 'radar-sweep-badge-20261114-makeup-v1'
    assert campaign in notice['body']
    order = draw_order(campaign, seal, beacon['randomness'], tickets)
    return dict(campaign=campaign,round=rnd,seal_sha256=seal,participants=len(order),winners=order[:2],order=order)

if __name__ == '__main__':
    print(json.dumps(calculate(),indent=2))
