# Author: PandaRE
# Tested on: d5acf44658f0dce90bd160f15d8e07a96938c81661d87dc7e9cb0107863bfb90

import sys, os, re, json
from collections import Counter

MASK64 = (1 << 64) - 1
MARKERS = {0x4268: 'string', 0x4269: 'int', 0x426A: 'bool', 0x426E: 'dict'}
CODE_WEIGHTS = {0x00:6, 0x48:5, 0x24:4, 0x8b:3, 0x89:3, 0x44:2, 0x40:2, 0x4c:2,
                0x8d:2, 0xe8:2, 0x85:1, 0x74:1, 0x75:1, 0xff:1, 0x41:1, 0xc0:1,
                0x50:1, 0x84:1, 0x8c:1, 0x90:1}
RES_RE  = re.compile(r'runtime::resource_get_(string_dictionary|string|int|bool)\s*\(\s*@([a-z_][a-z0-9_]*)')
NAME_RE = re.compile(r'^[a-z_][a-z0-9_]{2,60}$')

def qword(data, off):
    return int.from_bytes(data[off:off+8], 'little')

def get_key(data):
    for i in range(min(256, (len(data) - 0x78) // 0x58)):
        off = 0x78 + i * 0x58
        if off + 0x10 > len(data):
            break
        seed = qword(data, off)
        if seed == 0 or seed % 2 == 0:
            continue
        t = (qword(data, off + 8) - seed - (i + 1)) & MASK64
        return (t * pow(seed, -1, 1 << 64)) & MASK64
    return None

def read_header(data, key):
    P0, P1 = qword(data, 0), qword(data, 8)
    P4, P5 = qword(data, 0x20), qword(data, 0x28)
    R0, R1, R3 = qword(data, 0x50), qword(data, 0x58), qword(data, 0x68)
    return {'magic':   (P4 - key - P0*P1 - P5) & MASK64,
            'entries': ((R3 - key*R0) + R1) & MASK64}

def read_entry(data, off, key):
    s = qword(data, off)
    return {'id':       (qword(data, off + 8)    - key*s - s) & MASK64,
            'parent':   (qword(data, off + 0x10) - key + 3*s) & MASK64,
            'name_ref': (qword(data, off + 0x18) - key*(s + 5) + 2*s) & MASK64,
            'size':     (qword(data, off + 0x20) - key - 7*s) & MASK64,
            'flag':     1 if ((qword(data, off + 0x38) - 3*key + 3*s) & MASK64) != 0 else 0,
            'k':        (qword(data, off + 0x40) - key*s + 4*s) & 0xFF}

def cnt_xor(data, K):
    if not K or not data:
        return bytes(data)
    out = bytearray(data)
    c = 8
    for i in range(len(out)):
        c = (c*3 + 15) & 0xFF
        if c > K*3:
            c = (c - K) & 0xFF
        out[i] ^= (K + c) & 0xFF
    return bytes(out)

def _key256(data):
    key = bytearray(256)
    for col in range(256):
        stripe = data[col::256]
        cc = Counter(stripe)
        best_k, best_s = 0, -1
        for k in range(256):
            score = sum(w * cc.get(v ^ k, 0) for v, w in CODE_WEIGHTS.items())
            if score > best_s:
                best_s, best_k = score, k
        key[col] = best_k
    return bytes(key)

def xor256(data):
    if len(data) < 0x1000:
        return bytes(data)
    k = _key256(data)
    return bytes(data[i] ^ k[i % 256] for i in range(len(data)))

def linear_xor(data, A, B):
    return bytes(data[i] ^ ((A + B*i) & 0xFF) for i in range(len(data)))

def paired_strings(data, min_len=3):
    out, seen = [], set()
    for start in (0, 1):
        i, n = start, len(data)
        while i < n - 6:
            k = data[i+1]; j = i; buf = bytearray(); good = 0
            while j+1 < n and data[j+1] == k:
                b = data[j] ^ k
                if 0x20 <= b < 0x7F:
                    buf.append(b); good += 1; j += 2
                else:
                    break
            if good >= min_len:
                s = bytes(buf).decode('latin1')
                if (i, s) not in seen:
                    seen.add((i, s)); out.append((i, s))
                i = j
            else:
                i += 1
    return sorted(out)

def read_block(payload, off):
    if off + 8 > len(payload):
        return None
    b = payload[off:off+8]
    K = b[4]
    if b[5] != K or b[6] != K or b[7] != K:
        return None
    return int.from_bytes(bytes(b[j] ^ K for j in range(4)), 'little'), K

def find_markers(payload, start):
    out, i = [], start
    while i < len(payload) - 8:
        r = read_block(payload, i)
        if r and r[0] in MARKERS:
            out.append((i, r[0]))
        i += 1
    return out

def read_int(payload, off):
    r = read_block(payload, off)
    return r[0] if r else None

def read_bool(payload, off):
    if off + 8 > len(payload):
        return None
    b = payload[off:off+8]
    return bool((b[6] ^ b[7]) & 1)

def collect_types(strings):
    t = {}
    for _, s in strings:
        for kind, name in RES_RE.findall(s):
            t[name] = {'string_dictionary': 'dict', 'string': 'string',
                       'int': 'int', 'bool': 'bool'}[kind]
    return t

def parse_pool(payload):
    strings = paired_strings(payload, 3)
    if not strings:
        return {}
    types = collect_types(strings)
    if not types:
        return {}
    is_name = lambda s: (s.strip() in types) or bool(NAME_RE.match(s.strip()))

    first = next((i for i, (_, s) in enumerate(strings) if s.strip() in types), None)
    if first is None:
        return {}
    start_i = first
    while start_i > 0:
        prev = strings[start_i - 1][1].strip()
        pp = strings[start_i - 2][1].strip() if start_i >= 2 else None
        if is_name(prev):
            start_i -= 1
        elif pp is not None and is_name(pp):
            start_i -= 2
        else:
            break

    pool_start = strings[start_i][0]
    pool = [(o, s.strip()) for o, s in strings[start_i:]]
    markers = find_markers(payload, pool_start)

    typed = []
    for off, val in markers:
        kind = MARKERS[val]
        if kind == 'int':
            typed.append(('int', read_int(payload, off + 8)))
        elif kind == 'bool':
            typed.append(('bool', read_bool(payload, off + 8)))
        else:
            typed.append((kind, None))

    idx = [0]
    def take():
        if idx[0] < len(typed):
            v = typed[idx[0]]; idx[0] += 1
            return v
        return (None, None)

    cfg, open_dict, i = {}, None, 0
    while i < len(pool):
        _, s = pool[i]
        t = types.get(s)
        nxt = pool[i+1][1] if i + 1 < len(pool) else None
        if t is None and is_name(s):
            peek = typed[idx[0]][0] if idx[0] < len(typed) else None
            if peek in ('int', 'bool', 'dict'):
                t = peek
            elif nxt is not None and nxt not in types:
                t = 'string'

        if t == 'string':
            take()
            if nxt is not None:
                cfg[s] = nxt; i += 2; continue
        elif t == 'int':
            _, v = take(); cfg[s] = v; i += 1; continue
        elif t == 'bool':
            _, v = take(); cfg[s] = v; i += 1; continue
        elif t == 'dict':
            take(); open_dict = s; cfg[s] = []; i += 1; continue
        elif open_dict and not is_name(s):
            if nxt and nxt.isdigit():
                port = int(nxt)
                if 1 <= port <= 65535:
                    cfg[open_dict].append({'host': s, 'port': port})
                    i += 2; continue
        i += 1

    return cfg

def open_container(data):
    if len(data) < 0x100:
        return None
    key = get_key(data)
    if key is None:
        return None
    hdr = read_header(data, key)
    n = hdr['entries']
    if not (1 <= n <= 0x10000) or 0x78 + n*0x58 > len(data):
        return None
    return key, hdr

def dec_str(data, K):
    if len(data) < 2 or len(data) % 2 != 0:
        return None
    def ok(x):
        try:
            s = x.decode('utf-16-le').rstrip('\x00')
        except UnicodeDecodeError:
            return None
        if s and all(c.isprintable() or c in '\r\n\t' for c in s):
            return s
        return None
    r = ok(cnt_xor(data, K))
    if r:
        return r
    if len(data) >= 0x100:
        r = ok(xor256(data))
        if r:
            return r
    if len(data) >= 6:
        double_B = (data[3] - data[1]) & 0xFF
        for B in ((double_B >> 1) & 0xFF, ((double_B >> 1) + 0x80) & 0xFF):
            A = (data[1] - B) & 0xFF
            r = ok(linear_xor(data, A, B))
            if r:
                return r
    return None

def rsrc_walk(data, entries):
    kids_of = {}
    for e in entries:
        kids_of.setdefault(e['parent'], []).append(e)
    pairs = {}
    for _, kids in kids_of.items():
        kids = sorted(kids, key=lambda x: x['id'])
        if len(kids) != 4:
            continue
        blobs = [data[k['data_offset']:k['data_offset']+k['size']] for k in kids]
        name  = dec_str(blobs[1], kids[1]['k']) if kids[1]['size'] > 0 else None
        value = dec_str(blobs[3], kids[3]['k']) if kids[3]['size'] > 0 else None
        if name and value:
            pairs[name] = value
    return pairs

def unwrap(raw, K, flag):
    a = cnt_xor(raw, K) if (flag and K) else raw
    if parse_pool(a):
        return a
    if len(raw) >= 0x1000:
        b = xor256(raw)
        if parse_pool(b):
            return b
    return a

def run(path):
    data = open(path, 'rb').read()
    result = {}
    opened = open_container(data)
    resources = {}
    if opened:
        key, hdr = opened
        n = hdr['entries']
        payload_start = 0x78 + n*0x58
        entries = [read_entry(data, 0x78 + i*0x58, key) for i in range(n)]
        cum = 0
        for e in entries:
            e['data_offset'] = payload_start + cum
            cum += e['size']
        biggest = max(range(len(entries)), key=lambda i: entries[i]['size'])
        e = entries[biggest]
        raw = data[e['data_offset']:e['data_offset']+e['size']]
        payload = unwrap(raw, e['k'], e['flag'])
        resources = rsrc_walk(data, entries)
    else:
        payload = data
    result['persistence'] = resources
    result['config'] = parse_pool(payload)
    return result

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: cncmachinerms_config_extract.py <encrypted payload>", file=sys.stderr)
        sys.exit(1)
    if len(sys.argv) == 2:
        out = run(sys.argv[1])
    else:
        out = {'samples': [run(p) for p in sys.argv[1:]]}
    print(json.dumps(out, indent=2, default=str, ensure_ascii=False))
