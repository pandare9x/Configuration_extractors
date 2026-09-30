# Author: PandaRE
# Tested on: d5acf44658f0dce90bd160f15d8e07a96938c81661d87dc7e9cb0107863bfb90

import sys, json
from collections import Counter

W = {0x00:6,0x48:5,0x24:4,0x8b:3,0x89:3,0x44:2,0x40:2,0x4c:2,0x8d:2,0xe8:2,
     0x85:1,0x74:1,0x75:1,0xff:1,0x41:1,0xc0:1,0x50:1,0x84:1,0x8c:1,0x90:1}

def get_key(payload):
    key = bytearray(256)
    for c in range(256):
        col = payload[c::256]
        cc = Counter(col)
        best_k, best_s = 0, -1
        for k in range(256):
            s = sum(w * cc.get(v ^ k, 0) for v, w in W.items())
            if s > best_s: best_s, best_k = s, k
        key[c] = best_k
    return bytes(key)

def decrypt(data, key):
    return bytes(data[i] ^ key[i % 256] for i in range(len(data)))

def get_offset(data):
    import math
    for o in range(0, len(data), 0x1000):
        ch = data[o:o+0x1000]
        if not ch: continue
        c = Counter(ch); n = len(ch)
        h = -sum((v/n)*math.log2(v/n) for v in c.values())
        if h > 7.5:
            return o & ~0xFFFF
    return 0x20000

def get_str(data):
    out, seen = [], set()
    for start in (0, 1):
        i, n = start, len(data)
        while i < n - 6:
            k = data[i+1]; j = i; pt = bytearray(); good = 0
            while j+1 < n and data[j+1] == k:
                b = data[j] ^ k
                if 0x20 <= b < 0x7F:
                    pt.append(b); good += 1; j += 2
                else: break
            if good >= 3:
                s = bytes(pt).decode('latin1')
                if (i, s) not in seen:
                    seen.add((i, s)); out.append((i, s))
                i = j
            else: i += 1
    return sorted(out)

def read_marker(data, off):
    block = data[off:off+8]
    if len(block) < 8: return None
    k = block[7]
    if not all(block[i] == k for i in range(4, 8)): return None
    return int.from_bytes(bytes(block[i]^k for i in range(4)), 'little')

data = open(sys.argv[1],'rb').read()
po = get_offset(data)
key = get_key(data[po:])
full = decrypt(data, key)
strings = get_str(full)

marker_counts = Counter()
candidates = []
for off, name in strings:
    m = read_marker(full, off + len(name)*2)
    if m is not None and m > 0:
        marker_counts[m] += 1
        candidates.append((off, name, m))

if not marker_counts:
    print("{}"); sys.exit(0)

mode_marker = marker_counts.most_common(1)[0][0]
valid_markers = {m for m in marker_counts if abs(m - mode_marker) <= 64}
fields = [(o, n, m) for o, n, m in candidates if m in valid_markers]

def is_val_leaf(off, name):
    m = read_marker(full, off + len(name)*2)
    return m is None or m not in valid_markers

cfg = {}
for i, (off, name, marker) in enumerate(fields):
    value_off = off + len(name)*2 + 8
    next_off = fields[i+1][0] if i+1 < len(fields) else len(full)

    val_block = full[value_off:value_off+8]
    is_int_pattern = False
    if len(val_block) == 8:
        k = val_block[7]
        is_int_pattern = all(val_block[j] == k for j in range(4, 8))

    inner = [(o, s) for o, s in strings
             if value_off <= o < next_off
             and s.strip() and is_val_leaf(o, s)]

    if is_int_pattern:
        cfg[name] = int.from_bytes(bytes(val_block[j]^k for j in range(4)), 'little')
    elif not inner:
        cfg[name] = bool((val_block[6] ^ val_block[7]) & 1)
    elif len(inner) == 1:
        cfg[name] = inner[0][1]
    else:
        pairs, kk = [], 0
        while kk+1 < len(inner):
            host, port = inner[kk][1], inner[kk+1][1]
            if port.isdigit() and 1 <= int(port) <= 65535:
                pairs.append([host, port]); kk += 2
            else: kk += 1
        cfg[name] = pairs

print(json.dumps(cfg, indent=2))
