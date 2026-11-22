"""In-process coding ECU for tests: implements the UDS write choreography and verifies the seed/key and the coding
signature exactly as the real module would (raising sig^e and comparing), so a write that this accepts is one the car
would accept. No sockets. See nbtcoding/write.py."""
import hashlib, os
from nbtcoding import sign


class FakeEcu:
    def __init__(self, coding, l3: sign.Key, ncd: sign.Key, caf, btld: int, tester_id: int = 0):
        self.coding = {a.upper(): bytearray(b) for a, b in coding.items()}
        self.l3, self.ncd, self.btld, self.tester_id = l3, ncd, btld, tester_id
        self.content, self.sign_dg = sign.scheme_from_caf(caf)
        self.session = 0x01
        self.seed = None
        self.unlocked = False
        self.reset_done = False

    def _nrc(self, sid, code):
        return bytes([0x7F, sid, code])

    def request(self, uds, tgt=None):
        sid = uds[0]
        if sid == 0x10:                                   # session
            self.session = uds[1]
            if uds[1] != 0x41:
                self.unlocked = False
            return bytes([0x50, uds[1]])
        if sid == 0x27 and uds[1] == 0x01:                # request seed
            if self.session != 0x41:
                return self._nrc(sid, 0x22)
            self.seed = os.urandom(8)
            return bytes([0x67, 0x01]) + self.seed
        if sid == 0x27 and uds[1] == 0x02:                # send key: verify it
            if not self.seed:
                return self._nrc(sid, 0x24)
            key = uds[2:]
            size = self.l3.size
            if len(key) != 4 + size:
                return self._nrc(sid, 0x35)
            sig = key[4:]
            m = int.from_bytes(hashlib.md5(self.tester_id.to_bytes(4, "big") + self.btld.to_bytes(4, "big") + self.seed).digest(), "little")
            got = pow(int.from_bytes(sign._wordswap(sig), "little"), self.l3.public_exponent, self.l3.modulus)
            if got != m:
                return self._nrc(sid, 0x35)               # invalidKey
            self.unlocked = True
            return bytes([0x67, 0x02])
        if sid == 0x2E:                                   # write datagroup
            if not self.unlocked:
                return self._nrc(sid, 0x33)               # securityAccessDenied
            did = "%02X%02X" % (uds[1], uds[2])
            self.coding[did] = bytearray(uds[3:])
            return bytes([0x6E, uds[1], uds[2]])
        if sid == 0x22:                                   # read datagroup
            did = "%02X%02X" % (uds[1], uds[2])
            return bytes([0x62, uds[1], uds[2]]) + bytes(self.coding.get(did, b""))
        if sid == 0x31:                                   # CheckCodingSignature
            coding = {a: bytes(b) for a, b in self.coding.items()}
            ok = sign.verify(coding, self.content, self.sign_dg, self.ncd)
            status = b"\x00" if ok else b"\x01"
            return bytes([0x71, uds[1], uds[2], uds[3]]) + status
        if sid == 0x11:                                   # reset
            self.reset_done = True
            return bytes([0x51, uds[1]])
        return self._nrc(sid, 0x11)
