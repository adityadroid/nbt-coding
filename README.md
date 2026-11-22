# nbt-coding

A small, dependency-free tool to **read and change BMW F-series coding** over an ENET (OBD-to-Ethernet) cable, with a
friendly local web GUI. Plain Python standard library, no installs, no E-Sys, no paid app.

> **Status:** reads and names every setting of FRM, KOMBI, CAS and the NBT head unit. **Writes FRM and KOMBI** from the
> GUI: their coding signer reproduces this car's own signatures. CAS stays read-only until its AES-CMAC tag is
> reproduced from a full read. The head unit is never written (the Android Auto mod lives there). The first real write
> on the car is still to come; the full write path is proven against a simulated module that checks the security
> handshake and the signature like the car does.

Tested on a 2014 F10 with the original NBT head unit.

## Why this is possible

On a 2014 F-series car coding is signed **offline**: there is no BMW server in the loop (online "Secure Coding" came
~2021+). Each module has a coding-description file (a **CAFD**) that says where every setting lives: a datagroup
address, a byte range, and a bit mask. With the CAFD, the module's coding key (recovered from your own PSdZData) and an
ENET cable, the tool can read, decode, re-sign and write coding.

## Install

Python 3.10+ only.

```bash
git clone https://github.com/adityadroid/nbt-coding
cd nbt-coding
python3 -m nbtcoding        # starts the GUI at http://127.0.0.1:8733
```

Plug the ENET cable into the OBD port. The tool finds the car's gateway by broadcast on the cable; set `NBT_HOST` to
force an address.

## You must supply BMW's files

This repo ships **no BMW data files**. You need, from your own PSdZData:

- the decrypted CAFD XML for each module in `cafd/` (e.g. `cafd/cafd_0000106d.caf.013_012_011.xml`);
- the module coding keys in `keys/` (`ncd_<BTLD>.json`, `l3_<BTLD>.json`, `cas_mac_<BTLD>.json`).

`cafd/`, `keys/` and `backups/` are git-ignored.

## Using the GUI

1. Pick a module and press **Read from car**. Every datagroup the CAFD declares is read, decoded and saved as a backup.
2. Each setting shows BMW's own name, its block name, its current value, the factory default, and whether it was
   changed. Shortcut chips jump to common features (welcome lights, mirrors, start/stop, lock horn, ...).
3. On a writable module, pick a new value in the setting's menu. Changes collect in the tray at the bottom.
4. **Review** reads the module again, saves a fresh backup, and shows exactly what would change (in BMW's words) and
   the exact steps it would send. Nothing is written.
5. **Write to car** needs the engine running or a charger on, and the owner phrase typed. The tool unlocks the module,
   writes the changed blocks and the new signature (signature last), reads them back, asks the module to check its own
   signature, restarts it only if that passes, and reads it back again.
6. **Undo**: pick any earlier backup and press **Review restore**. It goes through the same review and write.

Also available with no car: **Show saved read** (decode a saved probe) and **Browse CAFD**.

## Names

BMW strips every name in a CAFD to `"."`. `nbtcoding/names/<CAFD>.json` puts them back. They are imported from
[Open CAFD Map](https://github.com/shamair28/OpenCAFDMap) (MIT), which keeps BMW's original names from untrimmed CAFD
dumps keyed by each datagroup's exact function layout. A name is only applied when our datagroup's layout matches
exactly, so names never land where bits moved. For this car every datagroup of FRM, KOMBI, CAS and NBT matches.

```bash
git clone --depth 1 https://github.com/shamair28/OpenCAFDMap /tmp/ocm
python3 -m nbtcoding.import_names /tmp/ocm          # names every decrypted CAFD in cafd/
```

Hand-confirmed names already in a file win over imported ones.

## Command line

```bash
python3 -m nbtcoding.probe                       # find the gateway, read every module's SVK and coding blocks
python3 -m nbtcoding.sign                        # check each module's signer against the newest saved read
python3 -m nbtcoding.diff before.json after.json FRM   # settings that changed between two reads
python3 -m nbtcoding.write <probe.json> FRM [key]      # print a write plan (dry run only)
```

## Layout

```
nbtcoding/
  hsfz.py          ENET/HSFZ transport (UDS over TCP 6801)
  ecu.py           module -> address map, read VIN / CAFD id / datagroups
  probe.py         gateway discovery and the car probe
  caf.py           parse a decrypted CAFD into datagroups and functions
  decode.py        join CAFD + car bytes + names; classify each setting; save backups
  names.py         name overlay loader;  names/  one file per CAFD id
  import_names.py  import BMW names from Open CAFD Map by exact layout
  sign.py          RSA coding signer (NBT, FRM, KOMBI);  cas_mac.py  AES-CMAC for CAS
  write.py         the signed write choreography (gated)
  edit.py          GUI changes -> checked plan -> write; who may be written
  server.py        local web server;  web/  the GUI page
tests/             offline tests, including the GUI write path against a simulated FRM
```

## Safety

- Writes only modules whose signer reproduced this car's own signature; never the head unit.
- Every read and every review saves a full backup; any write can be undone from the GUI.
- A write refuses if the car's coding changed since the review, and never restarts a module whose signature check fails.
- Keep the engine running or a charger on during any write.
- This is for your own vehicle. No warranty; see `LICENSE`.

## Credits

Names: [Open CAFD Map](https://github.com/shamair28/OpenCAFDMap), MIT licence, Copyright (c) 2026 Open CAFD Map
contributors.
