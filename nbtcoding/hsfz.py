"""HSFZ (BMW High-Speed Fahrzeug-Zugang) transport over TCP 6801, plus UDP 6811 discovery.

Read-only building block for our own NBT SSH-unlock tool. No key is ever sent from this
file; it only frames UDS requests and parses responses. BMW ENET/HSFZ framing:

    [ payload_len : 4 bytes big-endian ][ control_word : 2 bytes ][ payload ]
    payload = [ src_addr : 1 ][ tgt_addr : 1 ][ uds bytes ... ]
    payload_len counts the control word? No -> it counts ONLY the payload (src+tgt+uds).

Control words seen on the wire:
    0x0001  diagnostic request / response (the real UDS message)
    0x0002  acknowledge (ZGW echoes the request header; no UDS payload we need)
    0x0011/0x0012  also ack/nack variants on some gateways
Discovery (UDP 6811): a 'vehicle identification request' broadcast; the ZGW answers with a
frame carrying its logical address, VIN and MAC. We only read it.
"""
import socket, struct, time

TESTER = 0xF4          # our logical tester address
HU_NBT = 0x63          # head unit (the ECU that rejected service 31)
ZGW    = 0x10          # central gateway

class HsfzError(Exception):
    pass

def _recv_exact(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        sock.settimeout(max(0.1, deadline - time.time()))
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise HsfzError("timeout waiting for %d bytes (got %d)" % (n, len(buf)))
        if not chunk:
            raise HsfzError("connection closed by car")
        buf += chunk
    return buf

def _read_frame(sock, deadline):
    hdr = _recv_exact(sock, 6, deadline)
    plen, ctrl = struct.unpack(">IH", hdr)
    payload = _recv_exact(sock, plen, deadline) if plen else b""
    return ctrl, payload

class Hsfz:
    def __init__(self, host, port=6801, src=TESTER, verbose=True):
        self.host, self.port, self.src, self.verbose = host, port, src, verbose
        self.sock = None

    def open(self, timeout=5):
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.verbose:
            print("[hsfz] connected to %s:%d" % (self.host, self.port))

    def close(self):
        if self.sock:
            self.sock.close(); self.sock = None

    def _send(self, tgt, uds, ctrl=0x0001):
        payload = bytes([self.src, tgt]) + uds
        frame = struct.pack(">IH", len(payload), ctrl) + payload
        if self.verbose:
            print("  -> [%02X->%02X] %s" % (self.src, tgt, uds.hex(" ")))
        self.sock.sendall(frame)

    def request(self, uds, tgt=HU_NBT, timeout=5, settle=0.3):
        """Send one UDS request to tgt, return the first real UDS response payload (bytes
        after src+tgt). Skips ack frames. Handles 0x7F ..0x78 'responsePending' by waiting."""
        self._send(tgt, uds)
        deadline = time.time() + timeout
        while True:
            ctrl, payload = _read_frame(self.sock, deadline)
            if ctrl in (0x0002, 0x0011, 0x0012):   # ack / nack echo, keep reading
                if self.verbose: print("  .. ack ctrl=0x%04x" % ctrl)
                continue
            if len(payload) < 2:
                raise HsfzError("short payload: %s" % payload.hex())
            src, dst, resp = payload[0], payload[1], payload[2:]
            if self.verbose:
                print("  <- [%02X->%02X] %s" % (src, dst, resp.hex(" ")))
            # UDS negative response 0x7F <sid> 0x78 = responsePending: keep waiting
            if len(resp) >= 3 and resp[0] == 0x7F and resp[2] == 0x78:
                deadline = time.time() + timeout
                continue
            time.sleep(settle)
            return resp

def discover(bcast="169.254.255.255", port=6811, timeout=3, verbose=True):
    """UDP vehicle-identification broadcast; returns list of (addr, raw) answers. Read-only."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(timeout)
    # HSFZ ident request: len=2, ctrl=0x0011 (ident request), no payload is common; some want 0x0001
    for ctrl in (0x0011, 0x0001):
        try:
            s.sendto(struct.pack(">IH", 0, ctrl), (bcast, port))
        except OSError as e:
            if verbose: print("[disc] send ctrl=0x%04x failed: %s" % (ctrl, e))
    out = []
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, addr = s.recvfrom(512)
        except socket.timeout:
            break
        out.append((addr[0], data))
        if verbose: print("[disc] %s: %s" % (addr[0], data.hex(" ")))
    s.close()
    return out
