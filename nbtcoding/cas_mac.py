"""CAS coding protection: a keyed MD5 over the coding (pure Python, stdlib only).

CAS does not RSA-sign its coding like the NBT/FRM/KOMBI head-unit-class modules. Its protection datagroup (37FD on CAFD
0000000F) holds a 16-byte tag, and its PSdZData key (sec_ncdkeys.xml, BTLD 0000074B) is a type-3 symmetric key of 16
bytes (32 bytes on disk = key + PKCS#7 padding). The tag is

    tag = MD5( key || content || key )

where content is every coding datagroup below the tag datagroup, in address order, exactly as stored (the SYSTEM
datagroup 37FC included). Proven 2026-11-22 against this car's full CAS read: it reproduces the car's own tag byte for
byte. (An earlier guess, AES-128-CMAC, did not match and is gone.)

CAS is the immobiliser / key module: write it only with a fresh backup, engine off is not required but a charger or
running engine is, and one setting at a time.
"""
from __future__ import annotations

import hashlib


def content_bytes(coding: dict, content_dgs) -> bytes:
    return b"".join(coding[a] for a in ("%04X" % d for d in content_dgs) if a in coding)


def tag(key: bytes, content: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("CAS key must be 16 bytes, got %d" % len(key))
    return hashlib.md5(key + content + key).digest()


def verify(coding: dict, content_dgs, sign_dg: int, key: bytes) -> bool:
    """Does CAS's stored 16-byte tag equal MD5(key || content || key)? Writes nothing."""
    stored = coding.get("%04X" % sign_dg, b"")
    return len(stored) == 16 and tag(key, content_bytes(coding, content_dgs)) == stored


def sign(coding: dict, content_dgs, key: bytes) -> bytes:
    """The 16-byte CAS tag for the current content."""
    return tag(key, content_bytes(coding, content_dgs))
