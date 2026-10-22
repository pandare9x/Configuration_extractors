# Author: PandaRE
# Tested on: f938cdcd4098e934f299771ae1fdd819827a0ef98ef35c9f848dd1c96b3d0f25

import sys
import struct
import hashlib
import argparse

try:
    import aplib
except ImportError:
    print("ERROR: aplib not installed. Run: pip install aplib")
    sys.exit(1)

API_HASHES = [
    b"\x6c\x1a\xa7\x91",
    b"\x46\x5c\x31\xe8",
    b"\xef\x2b\xdd\x68",
    b"\x55\x5c\x7b\x1d",
    b"\x4e\xd9\x0c\x35",
    b"\x19\xd2\xd7\x3d",
    b"\xaa\xe1\xf0\x13",
]

HASH_SEED = struct.pack("<I", 0x6C6C6A62)


def scan(data):
    candidates = []

    for i in range(len(data) - 142):
        if data[i] != 0xE8:
            continue

        rel = struct.unpack_from("<i", data, i + 1)[0]
        code_addr = i + 5 + rel

        if code_addr < 0 or code_addr >= len(data):
            continue

        decomp_sz = struct.unpack_from("<I", data, i + 5)[0]
        comp_sz = struct.unpack_from("<I", data, i + 9)[0]

        if comp_sz == 0 or decomp_sz == 0:
            continue
        if comp_sz > len(data) or decomp_sz > 100_000_000:
            continue
        if decomp_sz <= comp_sz:
            continue

        if i + 142 + comp_sz > len(data):
            continue

        code_region = data[code_addr:min(code_addr + 0x600, len(data))]
        matched = sum(1 for h in API_HASHES if h in code_region)
        if HASH_SEED not in code_region:
            continue
        if matched < 3:
            continue

        candidates.append((i, comp_sz, decomp_sz, matched))

    return candidates


def decrypt(data, sc_offset):
    decomp_sz = struct.unpack_from("<I", data, sc_offset + 5)[0]
    comp_sz = struct.unpack_from("<I", data, sc_offset + 9)[0]
    xor_key = data[sc_offset + 13 : sc_offset + 13 + 128]
    enc_start = sc_offset + 142
    enc_data = bytearray(data[enc_start : enc_start + comp_sz])

    for i in range(len(enc_data)):
        enc_data[i] ^= xor_key[i % 128]

    payload = aplib.decompress(bytes(enc_data))

    if len(payload) != decomp_sz:
        print(f"  WARNING: decompressed {len(payload):,} bytes, header says {decomp_sz:,}")

    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = f.read()

    print(f"Input:  {args.input}")
    print(f"Size:   {len(data):,} bytes")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")

    candidates = scan(data)

    if not candidates:
        print("ERROR: No Brambly shellcode found in input file.")
        sys.exit(1)

    print(f"Found {len(candidates)} shellcode location(s):")
    for idx, (off, comp, decomp, hits) in enumerate(candidates):
        print(f"  [{idx}] offset=0x{off:X}  compressed={comp:,}  decompressed={decomp:,}")

    for idx, (off, comp, decomp, hits) in enumerate(candidates):
        try:
            payload = decrypt(data, off)
        except Exception as e:
            print(f"  FAILED: {e}")
            continue

        sha256 = hashlib.sha256(payload).hexdigest()
        is_payload_pe = payload[:2] == b"MZ"

        print(f"  Size:   {len(payload):,} bytes")
        print(f"  SHA256: {sha256}")
        print(f"  PE:     {is_payload_pe}")

        if args.output:
            out_path = args.output if len(candidates) == 1 else f"{args.output}.{idx}"
        else:
            out_path = args.input + "_payload.bin"
            if len(candidates) > 1:
                out_path = f"{args.input}_payload_{idx}.bin"

        with open(out_path, "wb") as f:
            f.write(payload)
        print(f"  Saved:  {out_path}")


if __name__ == "__main__":
    main()
