"""CAS coding protection: AES-128-CMAC (pure Python, stdlib only).

CAS (and some other body modules) do not RSA-sign their coding like the NBT/FRM/KOMBI head-unit-class modules. CAS's
coding "signature" datagroup is 16 bytes and its recovered key is 16 bytes — the shape of AES-128-CMAC (NIST SP 800-38B).
This module implements AES-128 (encrypt only, which is all CMAC needs) and CMAC with no third-party dependency, so it can
verify and produce CAS's 16-byte tag the same way the other modules' RSA signer does.

UNPROVEN against the car until a full CAS read (all content datagroups + the tag at ncdSignAddress) lets verify()
reproduce CAS's existing tag. The AES-CMAC itself is proven here against the NIST test vectors (tests/). Writing CAS is
the highest risk (immobiliser/keys) and stays last regardless.
"""
from __future__ import annotations

# ---- AES-128 (FIPS-197), encrypt only -------------------------------------------------------------------------------
_SBOX = []
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _init_sbox():
    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _init_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _key_expansion(key: bytes):
    assert len(key) == 16
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return w


def _encrypt_block(block: bytes, w) -> bytes:
    s = [list(block[i:i + 4]) for i in range(0, 16, 4)]   # column-major state

    def add_round_key(rnd):
        for c in range(4):
            for r in range(4):
                s[c][r] ^= w[rnd * 4 + c][r]

    add_round_key(0)
    for rnd in range(1, 11):
        s2 = [[_SBOX[s[c][r]] for r in range(4)] for c in range(4)]        # SubBytes
        row = [[s2[c][r] for c in range(4)] for r in range(4)]             # rows
        for r in range(4):
            row[r] = row[r][r:] + row[r][:r]                              # ShiftRows
        s2 = [[row[r][c] for r in range(4)] for c in range(4)]
        if rnd != 10:                                                     # MixColumns
            for c in range(4):
                a = s2[c]
                s2[c] = [_mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3],
                         a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                         a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3),
                         _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)]
        s = s2
        add_round_key(rnd)
    return bytes(s[c][r] for c in range(4) for r in range(4))


# ---- CMAC (NIST SP 800-38B) -----------------------------------------------------------------------------------------
def _dbl(b: bytes) -> bytes:
    n = int.from_bytes(b, "big") << 1
    if b[0] & 0x80:
        n ^= 0x87
    return (n & ((1 << 128) - 1)).to_bytes(16, "big")


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    w = _key_expansion(key)
    L = _encrypt_block(b"\x00" * 16, w)
    k1 = _dbl(L)
    k2 = _dbl(k1)
    if len(msg) and len(msg) % 16 == 0:
        blocks = [msg[i:i + 16] for i in range(0, len(msg), 16)]
        last = bytes(a ^ b for a, b in zip(blocks[-1], k1))
        blocks[-1] = last
    else:
        pad = msg + b"\x80" + b"\x00" * (15 - (len(msg) % 16))
        blocks = [pad[i:i + 16] for i in range(0, len(pad), 16)]
        blocks[-1] = bytes(a ^ b for a, b in zip(blocks[-1], k2))
    x = b"\x00" * 16
    for blk in blocks:
        x = _encrypt_block(bytes(a ^ b for a, b in zip(x, blk)), w)
    return x


# ---- CAS coding MAC -------------------------------------------------------------------------------------------------
def content_bytes(coding: dict, content_dgs) -> bytes:
    return b"".join(coding[a] for a in ("%04X" % d for d in content_dgs) if a in coding)


def verify(coding: dict, content_dgs, sign_dg: int, key: bytes) -> bool:
    """Does CAS's stored 16-byte tag equal AES-CMAC(key, content)? UNPROVEN until a full CAS read confirms the layout."""
    tag = coding.get("%04X" % sign_dg, b"")
    if len(tag) != 16:
        return False
    return aes_cmac(key, content_bytes(coding, content_dgs)) == tag


def sign(coding: dict, content_dgs, key: bytes) -> bytes:
    """The 16-byte CAS tag for the current content. Only trustworthy once verify() has reproduced the car's own tag."""
    return aes_cmac(key, content_bytes(coding, content_dgs))
