# Author: PandaRE
# Tested on: 8e0300cf9eccdc1225289fa643514c9aa006d29b35a16ba97f57bcd168deafd0

import struct, sys, io, json, os, re, base64
from collections import Counter
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

HASH_CONST = 0x70736575
IMG_BASE = 0x400000
VERBOSE = False

def load_pe(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:2] != b'MZ':
        print(f"[!] Not a PE: {path}")
        return None
    lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if lfanew + 24 >= len(data):
        return None
    nsec = struct.unpack_from('<H', data, lfanew + 6)[0]
    optsz = struct.unpack_from('<H', data, lfanew + 20)[0]
    soff = lfanew + 24 + optsz
    secs = []
    for i in range(nsec):
        o = soff + i * 40
        if o + 40 > len(data):
            break
        nm = data[o:o+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vs = struct.unpack_from('<I', data, o + 8)[0]
        va = struct.unpack_from('<I', data, o + 12)[0]
        rs = struct.unpack_from('<I', data, o + 16)[0]
        rp = struct.unpack_from('<I', data, o + 20)[0]
        secs.append({'name': nm, 'va': va, 'vsize': vs, 'rawptr': rp, 'rawsize': rs})
    return {'data': data, 'sections': secs, 'e_lfanew': lfanew}


def rva2raw(secs, rva):
    for s in secs:
        if s['va'] <= rva < s['va'] + max(s['vsize'], s['rawsize']):
            return s['rawptr'] + (rva - s['va'])
    return None


def get_text(secs, pe_data):
    for s in secs:
        if s['name'] == '.text':
            return s, pe_data[s['rawptr']:s['rawptr'] + s['rawsize']], IMG_BASE + s['va']
    s = secs[0]
    return s, pe_data[s['rawptr']:s['rawptr'] + s['rawsize']], IMG_BASE + s['va']


def count_calls(code, base):
    cc = Counter()
    for i in range(len(code) - 5):
        if code[i] != 0xE8:
            continue
        rel = struct.unpack_from('<i', code, i + 1)[0]
        t = base + i + 5 + rel
        if IMG_BASE <= t < IMG_BASE + 0x200000:
            cc[t] += 1
    return cc


def locate_dec(pe_data, secs):
    _, code, base = get_text(secs, pe_data)
    needle = struct.pack('<I', HASH_CONST)
    locs = []
    p = 0
    while True:
        idx = code.find(needle, p)
        if idx == -1:
            break
        locs.append(idx)
        p = idx + 1
    if not locs:
        print("[!] Hash constant 0x70736575 not found")
        return code, base, 0

    cc = count_calls(code, base)
    if VERBOSE:
        for va, n in cc.most_common(10):
            print(f"    0x{va:08X}: {n} callers")

    PRO = bytes([0x55, 0x53, 0x57, 0x56])
    dec_va = None
    for co in locs:
        for k in range(co, max(0, co - 600), -1):
            if code[k:k+4] == PRO:
                cva = base + k
                if cc.get(cva, 0) >= 200:
                    if VERBOSE:
                        print(f"[*] Decrypt func: 0x{cva:08X} ({cc[cva]} callers)")
                    dec_va = cva
                    break
        if dec_va:
            break

    if dec_va is None:
        for va, n in cc.most_common(20):
            if 500 <= n <= 900:
                dec_va = va
                break

    if dec_va is None:
        print("[!] Decrypt function not found")
    return code, base, dec_va or 0


def parse_pushes(code, call_off):
    if call_off < 8:
        return None
    ws = max(0, call_off - 40)
    win = code[ws:call_off]

    enc_va = None
    enc_pos = None
    j = 0
    while j < len(win) - 4:
        if win[j] == 0x68:
            v = struct.unpack_from('<I', win, j + 1)[0]
            if IMG_BASE + 0x30000 <= v < IMG_BASE + 0x200000:
                enc_va = v
                enc_pos = j
        j += 1
    if enc_va is None:
        return None

    pre = win[:enc_pos]
    pushes = []
    k = 0
    while k < len(pre):
        if pre[k] == 0x6A and k + 1 < len(pre):
            pushes.append(pre[k + 1])
            k += 2
        elif pre[k] == 0x68 and k + 5 <= len(pre):
            pushes.append(struct.unpack_from('<I', pre, k + 1)[0])
            k += 5
        else:
            k += 1

    if len(pushes) >= 2:
        seed, length = pushes[-2], pushes[-1]
    elif len(pushes) == 1:
        seed = length = pushes[0]
    else:
        return None

    if length <= 0 or length > 10000 or seed > 0xFFFF:
        return None
    return {'enc': enc_va, 'length': length, 'seed': seed}


def get_callsites(code, base, dec_va):
    raw = []
    for i in range(len(code) - 5):
        if code[i] != 0xE8:
            continue
        rel = struct.unpack_from('<i', code, i + 1)[0]
        if base + i + 5 + rel == dec_va:
            raw.append((base + i, i))

    parsed = []
    for cva, coff in raw:
        a = parse_pushes(code, coff)
        if a:
            parsed.append((cva, a))

    seen = set()
    uniq = []
    for cva, a in parsed:
        k = (a['enc'], a['seed'], a['length'])
        if k not in seen:
            seen.add(k)
            uniq.append((cva, a))
    return raw, uniq


def init_emu(pe_data, secs):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import UC_X86_REG_ESP

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mx = max(s['va'] + s['vsize'] for s in secs)
    pesz = ((mx + 0xFFF) & ~0xFFF)
    mu.mem_map(IMG_BASE, pesz)
    hsz = secs[0]['rawptr']
    mu.mem_write(IMG_BASE, pe_data[:hsz])
    for s in secs:
        mu.mem_write(IMG_BASE + s['va'], pe_data[s['rawptr']:s['rawptr'] + s['rawsize']])

    STK = 0x10000000
    mu.mem_map(STK, 0x100000)
    OUT = 0x20000000
    mu.mem_map(OUT, 0x10000)
    RET = 0x30000000
    mu.mem_map(RET, 0x1000)
    mu.mem_write(RET, b'\xCC')

    dsec = next((s for s in secs if s['name'] == '.data'), None)
    dinit = pe_data[dsec['rawptr']:dsec['rawptr'] + dsec['rawsize']] if dsec else None

    return mu, {'stk': STK, 'out': OUT, 'ret': RET, 'dsec': dsec, 'dinit': dinit}


def emu_call(mu, ctx, dec_va, enc_va, length, seed):
    from unicorn import UcError
    from unicorn.x86_const import UC_X86_REG_ESP

    if ctx['dsec'] and ctx['dinit']:
        mu.mem_write(IMG_BASE + ctx['dsec']['va'], ctx['dinit'])

    mu.mem_write(ctx['out'], b'\x00' * min(length + 16, 0x10000))
    esp = ctx['stk'] + 0x100000 - 0x1000
    for v in [seed, length, enc_va, ctx['out']]:
        esp -= 4
        mu.mem_write(esp, struct.pack('<I', v & 0xFFFFFFFF))
    esp -= 4
    mu.mem_write(esp, struct.pack('<I', ctx['ret']))
    mu.reg_write(UC_X86_REG_ESP, esp)

    try:
        mu.emu_start(dec_va, ctx['ret'], timeout=5000000)
    except UcError:
        return None
    return bytes(mu.mem_read(ctx['out'], length))


M64 = 0xFFFFFFFFFFFFFFFF
M32 = 0xFFFFFFFF
MM3_C = 0x2C1B3C6D
SM64_LO = 0x7F4A7C15


def mul64(a, b):
    return (a * b) & M64


def xs64(st):
    st ^= (st << 11) & M64
    st ^= (st >> 5)
    st ^= (st << 31) & M64
    return st


def sm64_seed(idx):
    s = (idx * 0x9E3779B97F4A7C15) & M64
    s ^= 0xA7B3C1D9E5F2AB08
    s = (s + 0x517CC1B727220A95) & M64
    s ^= (s >> 16)
    s = mul64(s, 0xFF51AFD7ED558CCD)
    s ^= (s >> 15)
    s = mul64(s, 0xC4CEB9FE1A85EC53)
    s ^= (s >> 16)
    if s == 0:
        s = 1
    for _ in range((idx % 7) + 1):
        s = xs64(s)
    return s


def mm3_mix(st):
    v = (st >> 16) & M32
    v = ((v >> 15) ^ v) & M32
    v = (v * 0x2C1B3C6D) & M32
    v = ((v >> 12) ^ v) & M32
    v = (v * 0x297A2D39) & M32
    v = ((v >> 15) ^ v) & M32
    return v


def l1_decrypt(enc, seed_idx, sz):
    st = sm64_seed(seed_idx)
    out = bytearray(sz)
    off = 0
    while off + 4 <= sz:
        st = xs64(st)
        k = mm3_mix(st)
        for j in range(4):
            out[off + j] = enc[off + j] ^ ((k >> (j * 8)) & 0xFF)
        off += 4
    if off < sz:
        st = xs64(st)
        k = mm3_mix(st)
        while off < sz:
            out[off] = enc[off] ^ (k & 0xFF)
            off += 1
            k >>= 8
    return bytes(out)


def get_layer(pe_data, secs):
    _, code, _ = get_text(secs, pe_data)
    if code.find(struct.pack('<I', HASH_CONST)) != -1:
        return 'layer2'
    if code.find(struct.pack('<I', MM3_C)) != -1:
        return 'layer1'
    return None


def find_prng_all(code, base):
    needle = struct.pack('<I', SM64_LO)
    locs = []
    p = 0
    while True:
        idx = code.find(needle, p)
        if idx == -1:
            break
        locs.append(idx)
        p = idx + 1
    if not locs:
        return []

    csm = {}
    for i in range(len(code) - 5):
        if code[i] != 0xE8:
            continue
        rel = struct.unpack_from('<i', code, i + 1)[0]
        t = base + i + 5 + rel
        if IMG_BASE <= t < IMG_BASE + 0x200000:
            csm.setdefault(t, []).append(i)

    cands = []
    seen = set()
    for off in locs:
        for k in range(off, max(0, off - 50), -1):
            if code[k] == 0x55 and k + 2 < len(code) and code[k+1] == 0x8B and code[k+2] == 0xEC:
                cva = base + k
                if cva in seen:
                    break
                seen.add(cva)
                sites = csm.get(cva, [])
                if len(sites) >= 5:
                    pi = sum(1 for s in sites if s >= 2 and code[s - 2] == 0x6A)
                    pi += sum(1 for s in sites if s >= 5 and code[s - 5] == 0x68)
                    if pi / len(sites) > 0.5:
                        cands.append(cva)
                break
    return cands


def find_prng(code, base):
    needle = struct.pack('<I', SM64_LO)
    locs = []
    p = 0
    while True:
        idx = code.find(needle, p)
        if idx == -1:
            break
        locs.append(idx)
        p = idx + 1
    if not locs:
        return None

    csm = {}
    for i in range(len(code) - 5):
        if code[i] != 0xE8:
            continue
        rel = struct.unpack_from('<i', code, i + 1)[0]
        t = base + i + 5 + rel
        if IMG_BASE <= t < IMG_BASE + 0x200000:
            csm.setdefault(t, []).append(i)

    cands = {}
    for off in locs:
        for k in range(off, max(0, off - 50), -1):
            if code[k] == 0x55 and k + 2 < len(code) and code[k+1] == 0x8B and code[k+2] == 0xEC:
                cands[base + k] = csm.get(base + k, [])
                break

    best_va, best_n = None, -1
    for cva, sites in cands.items():
        if len(sites) < 5:
            continue
        pi = sum(1 for s in sites if s >= 2 and code[s - 2] == 0x6A)
        pi += sum(1 for s in sites if s >= 5 and code[s - 5] == 0x68)
        if pi > best_n:
            best_n = pi
            best_va = cva
    return best_va


def find_malloc(code, base, prng_va):
    hits = Counter()
    for i in range(len(code) - 5):
        if code[i] != 0xE8:
            continue
        rel = struct.unpack_from('<i', code, i + 1)[0]
        if base + i + 5 + rel != prng_va:
            continue
        for j in range(max(0, i - 80), i):
            if code[j] == 0xE8:
                rel2 = struct.unpack_from('<i', code, j + 1)[0]
                t2 = base + j + 5 + rel2
                if IMG_BASE <= t2 < IMG_BASE + 0x200000 and t2 != prng_va:
                    hits[t2] += 1
    if not hits:
        return None
    return hits.most_common(1)[0][0]


def get_l1_wrappers(code, base, secs, prng_va, malloc_va):
    wraps = []
    for i in range(len(code) - 10):
        is_pb = code[i] == 0x6A and i + 2 < len(code) and code[i + 2] == 0xE8
        is_pd = code[i] == 0x68 and i + 10 < len(code) and code[i + 5] == 0xE8

        if is_pb:
            seed = code[i + 1]
            co = i + 2
        elif is_pd:
            seed = struct.unpack_from('<I', code, i + 1)[0]
            co = i + 5
        else:
            continue

        rel = struct.unpack_from('<i', code, co + 1)[0]
        if base + co + 5 + rel != prng_va:
            continue

        asz = None
        for j in range(max(0, i - 80), i):
            if code[j] == 0x6A and j + 7 <= len(code) and code[j + 2] == 0xE8:
                rel2 = struct.unpack_from('<i', code, j + 3)[0]
                if base + j + 2 + 5 + rel2 == malloc_va:
                    asz = code[j + 1]
                    break
            if code[j] == 0x68 and j + 10 <= len(code) and code[j + 5] == 0xE8:
                rel2 = struct.unpack_from('<i', code, j + 6)[0]
                if base + j + 5 + 5 + rel2 == malloc_va:
                    asz = struct.unpack_from('<I', code, j + 1)[0]
                    break
        if asz is None:
            continue

        fstart = None
        for k in range(max(0, i - 80), i):
            if code[k] == 0x55 and k + 2 < len(code) and code[k+1] == 0x8B and code[k+2] == 0xEC:
                fstart = base + k
                break
        if fstart is None:
            continue

        wraps.append({'func': fstart, 'alloc': asz, 'seed': seed, 'size': asz - 1})

    seen = set()
    uniq = []
    for w in wraps:
        if w['func'] not in seen:
            seen.add(w['func'])
            uniq.append(w)

    va_ranges = [(IMG_BASE + s['va'], IMG_BASE + s['va'] + s['vsize']) for s in secs]
    for w in uniq:
        for i in range(len(code) - 10):
            if code[i] != 0xE8:
                continue
            rel = struct.unpack_from('<i', code, i + 1)[0]
            if base + i + 5 + rel != w['func']:
                continue
            for j in range(max(0, i - 12), i):
                if code[j] == 0x68:
                    addr = struct.unpack_from('<I', code, j + 1)[0]
                    if any(lo <= addr < hi for lo, hi in va_ranges):
                        w['enc_va'] = addr
                        break
            if 'enc_va' in w:
                break

    return [w for w in uniq if 'enc_va' in w]


def run_l1(pe):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UcError, UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_ESP, UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_EBP

    secs = pe['sections']
    pd = pe['data']
    _, code, base = get_text(secs, pd)

    if VERBOSE:
        print("[*] Layer 1 (splitmix64 + xorshift64 + murmurhash3)")

    prng_cands = find_prng_all(code, base)
    if not prng_cands:
        print("[!] No PRNG functions found")
        return 1

    all_wraps = []
    mva = None
    for pva in prng_cands:
        mv = find_malloc(code, base, pva)
        if mv is None:
            continue
        if mva is None:
            mva = mv
        all_wraps.extend(get_l1_wrappers(code, base, secs, pva, mv))

    seen = set()
    wraps = []
    for w in all_wraps:
        if w['func'] not in seen:
            seen.add(w['func'])
            wraps.append(w)

    if not wraps or mva is None:
        print("[!] No wrappers found")
        return 1

    if VERBOSE:
        print(f"[*] {len(wraps)} wrappers, {len(prng_cands)} PRNG funcs")

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mx = max(s['va'] + s['vsize'] for s in secs)
    pesz = ((mx + 0xFFF) & ~0xFFF)
    mu.mem_map(IMG_BASE, pesz)
    mu.mem_write(IMG_BASE, pd[:secs[0]['rawptr']])
    for s in secs:
        mu.mem_write(IMG_BASE + s['va'], pd[s['rawptr']:s['rawptr'] + s['rawsize']])

    STK = 0x10000000
    mu.mem_map(STK, 0x100000)
    HEAP = 0x20000000
    mu.mem_map(HEAP, 0x100000)
    RET = 0x30000000
    mu.mem_map(RET, 0x1000)
    mu.mem_write(RET, b'\xCC')

    hp = [HEAP]

    def mhook(uc, addr, sz, ud):
        if addr == mva:
            esp = uc.reg_read(UC_X86_REG_ESP)
            ra = struct.unpack('<I', bytes(uc.mem_read(esp, 4)))[0]
            asz = struct.unpack('<I', bytes(uc.mem_read(esp + 4, 4)))[0]
            b = hp[0]
            hp[0] += (asz + 0x10) & ~0xF
            uc.reg_write(UC_X86_REG_EAX, b)
            uc.reg_write(UC_X86_REG_ESP, esp + 4)
            uc.reg_write(UC_X86_REG_EIP, ra)

    mu.hook_add(UC_HOOK_CODE, mhook)

    dsec = next((s for s in secs if s['name'] == '.data'), None)
    dinit = pd[dsec['rawptr']:dsec['rawptr'] + dsec['rawsize']] if dsec else None

    results = []
    for w in sorted(wraps, key=lambda x: x.get('enc_va', 0)):
        if dsec and dinit:
            mu.mem_write(IMG_BASE + dsec['va'], dinit)
        hp[0] = HEAP
        mu.mem_write(HEAP, b'\x00' * 0x10000)

        esp = STK + 0x100000 - 0x1000
        esp -= 4
        mu.mem_write(esp, struct.pack('<I', w['enc_va']))
        esp -= 4
        mu.mem_write(esp, struct.pack('<I', RET))
        mu.reg_write(UC_X86_REG_ESP, esp)
        mu.reg_write(UC_X86_REG_EBP, 0)

        try:
            mu.emu_start(w['func'], RET, timeout=5000000)
        except UcError:
            continue

        eax = mu.reg_read(UC_X86_REG_EAX)
        if HEAP <= eax < HEAP + 0x100000:
            raw = bytes(mu.mem_read(eax, w['size']))
        elif IMG_BASE <= eax < IMG_BASE + pesz:
            raw = bytes(mu.mem_read(eax, w['size']))
        else:
            raw = bytes(mu.mem_read(HEAP, w['size']))

        if not all(32 <= c < 127 or c == 0 for c in raw):
            continue
        txt = raw.decode('ascii', errors='replace').rstrip('\x00')
        if not txt:
            continue

        results.append({
            'call_va': w['func'], 'enc_va': w['enc_va'],
            'seed': w['seed'], 'length': w['size'],
            'text': txt,
        })

    return results


def run_l2(pe):
    code, base, dec_va = locate_dec(pe['data'], pe['sections'])
    if not dec_va:
        return 1

    raw, uniq = get_callsites(code, base, dec_va)
    if VERBOSE:
        print(f"[*] {len(raw)} calls, {len(uniq)} unique")
    if not uniq:
        print("[!] No call sites found")
        return 1

    mu, ctx = init_emu(pe['data'], pe['sections'])
    if VERBOSE:
        print(f"[*] Emulating {len(uniq)} calls...")

    results = []
    for cva, a in sorted(uniq, key=lambda x: x[1]['enc']):
        d = emu_call(mu, ctx, dec_va, a['enc'], a['length'], a['seed'])
        if d is None:
            continue
        ok = all(32 <= b < 127 or b == 0 for b in d)
        txt = d.decode('ascii', errors='replace').rstrip('\x00') if ok else '[hex] ' + d.hex()
        results.append({
            'call_va': cva, 'enc_va': a['enc'],
            'seed': a['seed'], 'length': a['length'],
            'text': txt,
        })
    return results


def resolve_ddr(results):
    drops = []
    sm = em = None

    for r in results:
        t = r['text']
        if 'telegra.ph' in t and t.startswith('http') and t not in drops:
            drops.append(t)

    if not drops:
        return []

    markers = [t for r in results for t in [r['text']]
               if 1 <= len(t) <= 6 and not t.isalnum() and any(c in t for c in '.])([')]
    for s, e in [('r.]', ')0(')]:
        if s in markers and e in markers:
            sm, em = s, e
            break
    if sm is None:
        for c in markers:
            if ']' in c and sm is None:
                sm = c
            elif ')' in c and em is None:
                em = c

    resolved = []
    if VERBOSE:
        print(f"\n[*] Resolving {len(drops)} dead drop(s)...")
        if sm and em:
            print(f"    Markers: start={repr(sm)}  end={repr(em)}")

    for url in drops:
        try:
            req = Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            html = urlopen(req, timeout=15).read().decode('utf-8', errors='replace')
        except (URLError, HTTPError, OSError) as e:
            print(f"    [-] {url}: {e}")
            continue

        c2 = None
        if sm and em:
            i = html.find(sm)
            if i != -1:
                i += len(sm)
                j = html.find(em, i)
                if j != -1:
                    blob = re.sub(r'<[^>]+>', '', html[i:j]).strip()
                    try:
                        dec = base64.b64decode(blob).decode('ascii')
                        if re.match(r'^[\w.\-:]+$', dec) and '.' in dec:
                            c2 = dec
                    except Exception:
                        pass

        if c2 is None:
            for m in re.finditer(r'[A-Za-z0-9+/]{8,}={0,2}', html):
                try:
                    dec = base64.b64decode(m.group()).decode('ascii')
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', dec):
                        c2 = dec
                        break
                    if re.match(r'^[a-zA-Z0-9][\w.\-]*\.[a-zA-Z]{2,}$', dec):
                        c2 = dec
                        break
                except Exception:
                    continue

        if c2:
            resolved.append(c2)
            if VERBOSE:
                print(f"    [+] {url} -> {c2}")
    return resolved


def sum(results, pe, layer):
    sm = {
        'file': os.path.basename(pe.get('path', '')),
        'file_size': len(pe['data']),
        'layer': layer,
        'decoded': len(results),
    }

    sorted_r = sorted(results, key=lambda r: r['enc_va'])
    by_va = {r['enc_va']: r['text'] for r in sorted_r}
    vas = [r['enc_va'] for r in sorted_r]

    def next_txt(va):
        idx = vas.index(va) if va in vas else -1
        return by_va.get(vas[idx + 1]) if 0 <= idx < len(vas) - 1 else None

    for r in sorted_r:
        t = r['text']
        nt = next_txt(r['enc_va'])

        if nt == 'bt':
            sm['build_tag'] = t
        elif nt == 'bv':
            sm['build_version'] = t
        elif len(t) == 36 and t.count('-') == 4 and t[8] == '-':
            sm['operator_uuid'] = t
        elif 'telegra.ph' in t and t.startswith('http'):
            sm.setdefault('dead_drops', [])
            if t not in sm['dead_drops']:
                sm['dead_drops'].append(t)
        elif re.match(r'^[a-z0-9][a-z0-9.-]+\.(cc|cfd|xyz|top|icu|site|pro)$', t):
            if 'dns' not in t and 'cloudflare' not in t:
                sm.setdefault('c2_domains', [])
                if t not in sm['c2_domains']:
                    sm['c2_domains'].append(t)
        elif re.match(r'^acrid.*cfg', t):
            sm['config_format'] = t
        elif re.match(r'^campaign-', t):
            sm['campaign_tag'] = t
        elif re.match(r'^t-[A-Za-z0-9_-]{20,}$', t):
            sm['auth_token'] = t
        elif re.match(r'^doh-\w+-\w+-v\d', t):
            sm['protocol_version'] = t
        elif re.match(r'^(Sun|Mon|Tue|Wed|Thu|Fri|Sat) \w+ +\d', t) and len(t) > 20:
            sm['build_timestamp'] = t
    return sm


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <payload.exe>")
        return 1

    path = sys.argv[1]
    pe = load_pe(path)
    if pe is None:
        return 1
    pe['path'] = path

    layer = get_layer(pe['data'], pe['sections'])
    if layer is None:
        print("[!] No known encryption constants found")
        return 1

    results = run_l2(pe) if layer == 'layer2' else run_l1(pe)
    if isinstance(results, int):
        return results

    ddr = resolve_ddr(results)
    sm = sum(results, pe, layer)
    if ddr:
        sm['ddr_resolved'] = ddr
    for k in ('file', 'file_size', 'layer', 'decoded'):
        sm.pop(k, None)
    print(json.dumps(sm, indent=2, default=str))

    return 0


if __name__ == '__main__':
    sys.exit(main())
