"""Prove the pure-Python AES-128-CMAC against the NIST SP 800-38B test vectors (which also proves the AES)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from nbtcoding.cas_mac import aes_cmac, _encrypt_block, _key_expansion

def run():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    # FIPS-197 AES-128 single-block encryption vector
    assert _encrypt_block(bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
                          _key_expansion(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))).hex() == \
        "3925841d02dc09fbdc118597196a0b32", "AES-128 block vector failed"
    cases = {
        "": "bb1d6929e95937287fa37d129b756746",
        "6bc1bee22e409f96e93d7e117393172a": "070a16b46b4d4144f79bdd9dd04a287c",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411": "dfa66747de9ae63030ca32611497c827",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710": "51f0bebf7e3b9d92fc49741779363cfe",
    }
    for msg_hex, want in cases.items():
        got = aes_cmac(key, bytes.fromhex(msg_hex)).hex()
        assert got == want, "CMAC mismatch for %d-byte msg: %s != %s" % (len(msg_hex) // 2, got, want)
    print("OK: AES-128 and all four NIST AES-CMAC vectors pass")

if __name__ == "__main__":
    run()
