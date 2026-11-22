# nbt-coding

A small, dependency-free tool to **view (and later change) BMW F-series coding** over an ENET
(OBD-to-Ethernet) cable, with a friendly local web GUI. Built so you never depend on E-Sys or
any paid app — it is plain Python standard library, no installs.

> **Status: read-only.** It reads a module's coding, decodes it into a browsable, plain-English
> list, and saves a full backup every time. **Writing is deliberately disabled** until the
> coding signer is built and proven (see [Writing](#writing-not-built-yet)). It never changes
> the car yet.

Tested against the original **NBT** head unit of a 2014 F10. The same HSFZ/UDS read path is
standard across F-series modules (CAS, FRM, KOMBI, …); each needs its CAFD decoded first.

## Why this is possible

On a 2014 F-series car the coding is signed **offline** — there is no BMW server in the loop
(online "Secure Coding" came ~2021+). Each module has a coding-description file (a **CAFD**)
that says where every setting lives: a datagroup address, a byte range, and a bit mask. Given
the CAFD and an ENET cable, reading and decoding coding is just UDS `22 <datagroup>` over HSFZ.

## Install

Nothing to install — Python 3.10+ only.

```bash
git clone https://github.com/adityadroid/nbt-coding
cd nbt-coding
python3 -m nbtcoding        # starts the GUI at http://127.0.0.1:8733
```

Plug the ENET cable into the OBD port. The car answers on a link-local address
(`169.254.199.99` on the NBT). Set `NBT_HOST` to change it.

## Car probe (first step at the car)

```bash
python3 -m nbtcoding.probe          # ~1 min, ignition on, ENET cable in
```

Finds the gateway (HSFZ broadcast), then asks each known F-series module for its SVK (which CAFD it needs) and its raw
coding datagroups (`22 3000..300F`). **Read-only**: only ReadDataByIdentifier, plus a switch to the extended
diagnostic session and back if a module refuses reads in its default session. Everything goes to
`backups/probe-<time>.json` (git-ignored: it holds the VIN). The summary lists the CAFD ids to decode next.
`--scan` also tries every other address 0x01..0x7F.

## You must supply the CAFD files

This repo ships **no BMW data**. To decode a module you need its CAFD XML (from your own
PSdZData). Put the decoded files in `cafd/` (e.g. `cafd/cafd_00000ded.xml`), or point
`NBT_CAFD_DIR` at the folder that holds them. `cafd/` and `backups/` are git-ignored.

## Using the GUI

- **Read from car** — pick a module, click it. The tool reads the module's CAFD id from its own
  SVK, loads the matching CAFD, reads every USER datagroup, decodes it, and saves a backup to
  `backups/`.
- **Load CAFD** (offline) — browse what a module can do with no car connected.
- Every setting is shown in plain English: an **on/off** switch, a **choice** of values, or a
  **value** field, with its current value, the factory default, and whether it was changed.
- BMW ships CAFDs with the setting names stripped to `"."`. A setting is therefore known by its
  location. As you confirm what one does, add it to `nbtcoding/names/<CAFD_ID>.json` and it
  shows up named, with your description, in the GUI — no restart of meaning, just reload.

### Finding what a setting does (the safe way)

BMW ships the CAFDs with every setting named `"."`, so a setting is known only by its location. To find which one
controls a feature (mirror fold on lock, needle sweep, welcome lights, ...), don't guess a byte — **diff**:

1. `python3 -m nbtcoding.probe` (or GUI *Read from car*) — the "before".
2. Toggle the feature in the car: iDrive menu, key fob, whatever changes it.
3. Read again — the "after".
4. `python3 -m nbtcoding.diff before.json after.json <MODULE>` — it prints exactly the setting(s) that changed, with
   location and old → new value. That location is the feature.
5. Add that location to `nbtcoding/names/<CAFD>.json` and it shows up named everywhere.

No guessing, no risk: you only read, and you confirm the location against a real change you made.

## Friendly names overlay

```json
{
  "module": "HU_NBT",
  "functions": {
    "3000:0:0:01": {"name": "VIDEO_IN_MOTION", "desc": "Video while driving.",
                    "values": {"0": "Off", "1": "On"}}
  }
}
```

The key is the setting's location (`datagroup:start:end:mask`), which the GUI shows on every row.

## Layout

```
nbtcoding/
  hsfz.py      ENET/HSFZ transport (UDS over TCP 6801) — read-only framing, sends no keys
  ecu.py       read a module's coding over ENET; module→address map; writing is locked
  caf.py       parse a decoded CAFD XML into datagroups → functions
  decode.py    join CAFD + car bytes + names; classify each setting; save backups
  names.py     friendly-name overlay loader
  names/       overlay files, one per CAFD id
  server.py    the local web server (stdlib http.server only)
  web/         the GUI page
cafd/          you put decoded CAFD XML here (git-ignored)
backups/       a full backup is written here on every read (git-ignored)
```

## Writing (not built yet)

Writing coding needs a re-signed signature block (the SYSTEM datagroup at `ncdSignAddress`).
The plan, in order of risk:

1. Read + back up — **done**.
2. Prove the signer offline: re-sign the **unchanged** coding we read and check it matches the
   signature already in the car. No car write.
3. First write on a low-risk module (FRM — lights), with a battery charger on, then read back
   and verify.
4. Only then CAS (keys/immobiliser — a bad write can stop the car starting).

## Safety

- Read-only today; `ecu.write_datagroup` refuses.
- A full backup is saved on every read, so any change can be reverted.
- Keep a battery charger on the car during any coding session.
- This is for your own vehicle. No warranty — see `LICENSE`.
