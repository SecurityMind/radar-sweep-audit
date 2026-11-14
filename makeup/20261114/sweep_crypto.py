"""Public byte protocol. No clock, wallet, or network dependency."""
import hashlib
import json
import struct

CHAIN = {
    'hash': '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
    'public_key': '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
    'genesis_time': 1692803367, 'period': 3, 'schemeID': 'bls-unchained-g1-rfc9380',
}
DST = b'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_'

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def round_at(timestamp):
    # First beacon at or after the target; integral milliseconds at caller.
    import math
    return math.ceil((timestamp - CHAIN['genesis_time']) / CHAIN['period']) + 1

def round_time(r):
    return CHAIN['genesis_time'] + (r - 1) * CHAIN['period']

def verify_beacon(beacon, expected_round):
    """quicknet: SHA256(uint64_be(round)) signed on G1; randomness=SHA256(sig)."""
    from py_ecc.bls.hash_to_curve import hash_to_G1
    from py_ecc.bls.point_compression import decompress_G1, decompress_G2
    from py_ecc.optimized_bls12_381 import G2, pairing, multiply, curve_order, is_inf
    if type(beacon.get('round')) is not int or beacon['round'] != expected_round:
        raise ValueError('beacon_round_mismatch')
    try:
        sig = bytes.fromhex(beacon['signature'])
        if len(sig) != 48 or beacon['signature'] != sig.hex():
            raise ValueError()
        pk = bytes.fromhex(CHAIN['public_key'])
        s = decompress_G1(int.from_bytes(sig, 'big'))
        p = decompress_G2((int.from_bytes(pk[:48], 'big'), int.from_bytes(pk[48:], 'big')))
        if is_inf(s) or is_inf(p) or not is_inf(multiply(s, curve_order)) or not is_inf(multiply(p, curve_order)):
            raise ValueError()
        message = hashlib.sha256(struct.pack('>Q', expected_round)).digest()
        h = hash_to_G1(message, DST, hashlib.sha256)
        if pairing(p, h) != pairing(G2, s) or digest(sig) != beacon['randomness']:
            raise ValueError()
    except (KeyError, TypeError, ValueError, OverflowError, AssertionError):
        raise ValueError('beacon_signature_invalid') from None
    return {k: beacon[k] for k in ('round', 'randomness', 'signature')}

def draw_order(campaign_id, seal_sha256, randomness, tickets):
    if len(set(tickets)) != len(tickets):
        raise ValueError('duplicate_ticket')
    def lp(s):
        b = s.encode('ascii')
        return struct.pack('>I', len(b)) + b
    seed = hashlib.sha256(b'radar-sweep-v1\x00' + lp(campaign_id) + bytes.fromhex(seal_sha256) + bytes.fromhex(randomness)).digest()
    return sorted(tickets, key=lambda t: (hashlib.sha256(seed + lp(t)).digest(), t))
