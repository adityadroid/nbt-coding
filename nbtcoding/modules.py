"""Every coded module of this car (2014 F10 530d, probe 2026-11-22): diagnostic address, short name, what it does, and
the BTLD whose PSdZData key signs its coding. Each one's signer reproduced the car's own signature from a full read
(2026-11-22), so all are writable except the head unit (Android Auto lives there). Names with "?" are inferred from
the module's coding block names, not from BMW documentation."""
from __future__ import annotations

# (addr, name, what it does, BTLD, scheme)   scheme: "rsa" (BMWSigVerify, MD5) or "keyed-md5" (CAS)
MODULES = [
    (0x01, "ACSM", "Airbags and crash sensors", "00000906", "rsa"),
    (0x02, "SZL", "Steering column switches (wheel heating, paddles)", "0000036E", "rsa"),
    (0x06, "TRSVC_CAM", "Camera system (rear / top view) ?", "00000467", "rsa"),
    (0x12, "DME", "Engine (diesel DDE)", "00000C9D", "rsa"),
    (0x17, "EKPS", "Fuel pump control", "00001017", "rsa"),
    (0x18, "EGS", "Automatic gearbox", "00000C7C", "rsa"),
    (0x1C, "ICM", "Integrated chassis management", "00001E74", "rsa"),
    (0x26, "RSE", "Rear seat entertainment", "00001283", "rsa"),
    (0x29, "DSC", "Stability control / ABS", "00000F50", "rsa"),
    (0x2A, "EMF", "Electric parking brake ?", "000004AF", "rsa"),
    (0x30, "EPS", "Power steering", "00000E1D", "rsa"),
    (0x31, "DVD", "DVD changer", "00000848", "rsa"),
    (0x35, "TOUCH", "Controller / touch input timing ?", "000017AE", "rsa"),
    (0x37, "AMP", "Harman/Kardon amplifier", "000004B3", "rsa"),
    (0x3D, "MIRROR", "Interior mirror dimming ?", "00000704", "rsa"),
    (0x40, "CAS", "Keys, locks, start, comfort access (immobiliser)", "0000074B", "keyed-md5"),
    (0x41, "AHL_L", "Headlight leveling / adaptive light, left", "000017F0", "rsa"),
    (0x42, "AHL_R", "Headlight leveling / adaptive light, right", "000017F0", "rsa"),
    (0x43, "LED_L", "Headlight LED driver, left", "000018EB", "rsa"),
    (0x44, "LED_R", "Headlight LED driver, right", "000018EB", "rsa"),
    (0x4D, "SENS_L", "Chassis sensor module ?", "00000CE0", "rsa"),
    (0x4E, "SENS_R", "Chassis sensor module ?", "00000CE0", "rsa"),
    (0x56, "FZD", "Roof module (interior lights, sunroof, SOS)", "00000A6B", "rsa"),
    (0x5F, "FLA", "High-beam assistant camera", "00001087", "rsa"),
    (0x60, "KOMBI", "Instrument cluster", "000016E4", "rsa"),
    (0x63, "HU_NBT", "Head unit (Android Auto mod; never written)", "00001275", "rsa"),
    (0x64, "PDC", "Parking sensors", "000005F5", "rsa"),
    (0x67, "ZBE", "iDrive controller", "00001776", "rsa"),
    (0x6D, "TRSVC", "Top / rear view camera control", "000003E4", "rsa"),
    (0x72, "FRM", "Footwell module: lights, mirrors, windows", "0000106B", "rsa"),
    (0x78, "IHKA", "Climate control", "00002788", "rsa"),
]

BY_NAME = {m[1]: m for m in MODULES}
BY_ADDR = {"%02X" % m[0]: m for m in MODULES}


def addr_of(name: str) -> int:
    return BY_NAME[name][0]


def name_of(addr) -> str:
    key = addr if isinstance(addr, str) else "%02X" % addr
    return BY_ADDR.get(key.upper(), (0, key))[1]
