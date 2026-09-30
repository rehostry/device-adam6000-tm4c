#!/usr/bin/env python3
# Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive this image's declared capability inventory from its OWN bytes.

WHY THIS FILE EXISTS
--------------------
``attack.INTERFACE_INVENTORY`` carried ``"count": 4`` and ``"graded": 2`` as
**Python literals**, sourced from a prose note whose stated authority was
*"Advantech's own published capability set for the ADAM-6000 series"*.  Three
things were wrong, and each is a named trap on this fleet:

  * **a typed denominator is not re-derivable, so it is not falsifiable.**  No
    run would notice the image being swapped for one declaring something else.
  * **`"graded": 2` was an inert constant** -- a numerator no arm could move.
  * **the source was the PRODUCT, not the image.**  RULES §1d: the denominator
    is what *the image under test* declares.

This image carries **no service dispatch table** -- the ASCII command decoder is
a chain of inline character compares, and the tokens sit in scattered literal
pools, so there is nothing here of the shape ``digi-connectme-app``'s 41-record
table has.  Saying so plainly is part of the result.  What the image *does* carry
is six **declaration strings / string sets**, each located by a stated structural
predicate over maximal NUL-terminated printable runs, each with its raw bytes
pinned:

``A1 service_config_json``
    The firmware's own network-service configuration record template.  Located as
    **the unique** printable run that is a JSON object template every one of whose
    keys matches ``[A-Za-z]+(port|Port|En|Diag)``.  Uniqueness is ASSERTED at
    derive time: if the image ever contains two, the derivation refuses rather
    than picking one.  That is what removes our judgement from the selection.

``A2 enable_console_decls``
    printf templates with **exactly one** conversion naming an identifier whose
    last token is ``En``/``EN``/``Flag``, or containing the word ``enable``.

``A3 devsetting_decls``
    ``g_sDevSetting.<table>.<field> = %`` -- the firmware printing its own
    settings-structure fields.

``A4 boolean_enable_decls``    ``bEn<Name>=%``.

``A5 community_decl``
    ``uc<Name>Community:%s`` sets -- which is how the **trap** target is declared.

``A6 ascii_command_tokens``
    4-byte-aligned, slot-start (preceded by NUL), NUL-padded tokens of the form
    ``(ET|LS|GET|SET)[A-Z0-9]{2,10}`` with an optional trailing ``\\r``.
    ⚠ **The prefix set is OURS; the tokens and their count are the firmware's.**
    That is stated because it is the weakest step here.  A prefix-free version of
    this rule was tried first and collected 60 tokens including ``NAN``, ``INF``,
    ``RSA`` and ``A2000`` -- noise, not a capability set.
    ⚠ And the first version of the rule required a **NUL** terminator, which
    silently dropped every CR-terminated token (``LSMBTCP\\r``): a
    matcher-produced absence, the failure mode that has already wrongly removed
    an entry once on this fleet.

⚠ ``n`` is a **FLOOR**.  ``OTA_tcptls_connect_cb`` and ``[P2PTask] recvfrom=``
are further declared links that none of A1..A6 reaches; growing the denominator
that way needs a further independently-derived source, so it is REFERRED.  Note
the direction: acting on the referral can only make this fraction worse.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

RUN = re.compile(rb"[\x09-\x7e]{6,}\x00")
JKEY = re.compile(rb"\"([A-Za-z0-9_]+)\":")
JKEY_OK = re.compile(r"[A-Za-z]+(?:port|Port|En|Diag)\Z")
CONV = re.compile(rb"%[-0-9.lu]*[xXdus]")
ENABLE_ID = re.compile(rb"[A-Za-z_][A-Za-z0-9_.]*(?:En|EN|Flag)\b|enable")
A3_RE = re.compile(rb"^g_sDevSetting\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+) = %")
A4_RE = re.compile(rb"^ ?(bEn[A-Za-z][A-Za-z0-9]*)=%")
A5_RE = re.compile(rb"^(?:uc[A-Za-z]+Community:%s ?)+$")
A5_KEY = re.compile(rb"(uc[A-Za-z]+Community):")
A6_RE = re.compile(rb"(?:ET|LS|GET|SET)[A-Z0-9]{2,10}\r?\Z")


def _runs(buf: bytes) -> List[Tuple[int, bytes]]:
    return [(m.start(), m.group()[:-1]) for m in RUN.finditer(buf)]


def _blk(name: str, buf: bytes, hits: List[Tuple[int, str]],
         pred: str) -> Dict[str, Any]:
    if not hits:
        raise SystemExit("derive_inventory: block %s is empty" % name)
    lo = min(o for o, _ in hits)
    hi = max(o for o, _ in hits)
    hi = buf.find(b"\x00", hi) + 1
    span = buf[lo:hi]
    return {"name": name, "start": lo, "end": hi, "predicate": pred,
            "count": len(set(t for _, t in hits)),
            "hits": len(hits),
            "tokens": sorted(set(t for _, t in hits)),
            "tokens_in_order": [t for _, t in sorted(hits)],
            "offsets": sorted(o for o, _ in hits),
            "bytes_sha256": hashlib.sha256(span).hexdigest(),
            "bytes_len": len(span)}


def blocks(buf: bytes) -> Dict[str, Dict[str, Any]]:
    rs = _runs(buf)
    # A1 -- unique JSON service-configuration template
    a1c = []
    for off, s in rs:
        if not s.startswith(b'{"'):
            continue
        ks = [k.decode() for k in JKEY.findall(s)]
        if ks and all(JKEY_OK.match(k) for k in ks):
            a1c.append((off, s, ks))
    if len(a1c) != 1:
        raise SystemExit("derive_inventory: A1 is not unique (%d candidates) -- "
                         "refusing to choose one" % len(a1c))
    off, s, ks = a1c[0]
    a1 = _blk("service_config_json", buf, [(off, k) for k in ks],
              "the UNIQUE printable run that is a JSON object template all of "
              "whose keys match [A-Za-z]+(port|Port|En|Diag)")
    a1["template"] = s.decode()
    a1["start"], a1["end"] = off, off + len(s) + 1
    a1["bytes_sha256"] = hashlib.sha256(buf[a1["start"]:a1["end"]]).hexdigest()
    a1["bytes_len"] = a1["end"] - a1["start"]

    # A2 -- one-conversion enable declarations
    a2h = []
    for off, s in rs:
        if len(CONV.findall(s)) != 1:
            continue
        m = ENABLE_ID.search(s)
        if m:
            a2h.append((off, m.group().decode()))
    a2 = _blk("enable_console_decls", buf, a2h,
              "printf template with exactly one conversion naming an "
              "identifier ending in En/EN/Flag, or containing 'enable'")

    a3 = _blk("devsetting_decls", buf,
              [(o, A3_RE.match(s).group(2).decode()) for o, s in rs
               if A3_RE.match(s)],
              "g_sDevSetting.<table>.<field> = % declarations")
    a4 = _blk("boolean_enable_decls", buf,
              [(o, A4_RE.match(s).group(1).decode()) for o, s in rs
               if A4_RE.match(s)],
              "bEn<Name>=% declarations")
    a5h = []
    for o, s in rs:
        if A5_RE.match(s):
            a5h += [(o, k.decode()) for k in A5_KEY.findall(s)]
    a5 = _blk("community_decl", buf, a5h, "uc<Name>Community:%s sets")

    a6h = []
    for a in range(4, len(buf) - 4, 4):
        if buf[a - 1] != 0:
            continue
        e = buf.find(b"\x00", a)
        if e < a:
            continue
        t = buf[a:e]
        if not A6_RE.match(t):
            continue
        pad = (-(e + 1)) % 4
        if not all(c == 0 for c in buf[e + 1:e + 1 + pad]):
            continue
        a6h.append((a, t.decode().rstrip("\r")))
    a6 = _blk("ascii_command_tokens", buf, a6h,
              "4-byte-aligned NUL-padded slot-start token "
              "(ET|LS|GET|SET)[A-Z0-9]{2,10} with an optional trailing CR")
    return {"A1": a1, "A2": a2, "A3": a3, "A4": a4, "A5": a5, "A6": a6}


# ---------------------------------------------------------------------------
# The mapping from declared tokens to M8 entries.  COMMITTED AND AUDITABLE.
# ---------------------------------------------------------------------------
MAP: List[Dict[str, Any]] = [
    {"id": "modbus_tcp_502",
     "from": ["A1:MBEn", "A1:MBport", "A2:usMBTCPFlag", "A6:ETMBTCP",
              "A6:LSMBTCP", "A6:GETMBTCPPN"],
     "what": "Modbus/TCP server on tcp/502"},
    {"id": "http_config_server_80",
     "from": ["A1:WebEn", "A1:Webport", "A2:usWebSrvEn", "A6:ETWEBSRV"],
     "what": "HTTP configuration server on tcp/80"},
    {"id": "snmp_agent_161",
     "from": ["A2:usSNMPEn", "A2:enable", "A5:ucReadCommunity",
              "A5:ucWriteCommunity", "A6:ETSNMP", "A6:ETSNMPEN"],
     "what": "SNMP agent on udp/161"},
    {"id": "snmp_trap_client",
     "from": ["A5:ucTrapCommunity", "A6:ETTRAP"],
     "what": "SNMP TRAP client -- OUTBOUND, and an M8 entry under the "
             "2026-09-30 outbound-client ruling"},
    {"id": "sntp_client", "from": ["A6:ETSNTP", "A6:ETDT"],
     "what": "SNTP time client -- OUTBOUND"},
    {"id": "mqtt_client", "from": ["A3:ucEnMqtt", "A6:ETMQTT", "A6:ETMQTPC"],
     "what": "MQTT client to an external broker -- OUTBOUND"},
    {"id": "azure_iothub_client", "from": ["A3:ucEnAzureIoTHub"],
     "what": "Azure IoT Hub client -- OUTBOUND, a DIFFERENT peer and a "
             "different topic namespace from the plain broker above"},
    {"id": "dhcp_client", "from": ["A4:bEnDHCP"],
     "what": "DHCP client -- OUTBOUND"},
    {"id": "data_stream_push", "from": ["A1:DSport"],
     "what": "the Data Stream push service -- OUTBOUND to a collector"},
    {"id": "gcl_peer_service", "from": ["A1:GCLport"],
     "what": "the GCL / peer-to-peer service on its own port"},
    {"id": "netdiag_service", "from": ["A1:NetDiag"],
     "what": "the network-diagnostic service"},
    {"id": "ascii_command_service",
     "from": ["A6:ETUDP", "A6:ETCNT", "A6:ETWP", "A6:ETAH"],
     "what": "the ASCII configuration-command service.  ETCNT/ETWP/ETAH are "
             "further COMMANDS on this one seam, and RULES §1a is explicit that "
             "two commands over one seam are one interface -- so they map here "
             "rather than becoming entries of their own"},
]
SUBSTRATE: List[Dict[str, Any]] = [
    {"id": "tls_transport", "from": ["A6:ETSEC", "A6:ETTLS"],
     "why": "TLS/security parameters for the transports above; no endpoint of "
            "its own (RULES §1a substrate ruling)"},
]


def derive(image: bytes) -> Dict[str, Any]:
    bl = blocks(image)
    have = set("%s:%s" % (k, t) for k, b in bl.items() for t in b["tokens"])
    entries, unmapped = [], set(have)
    for e in MAP:
        ok = [f for f in e["from"] if f in have]
        unmapped -= set(ok)
        entries.append(dict(e, declared_by=ok, supported=bool(ok)))
    for sub in SUBSTRATE:
        unmapped -= set(f for f in sub["from"] if f in have)
    # A declared token this mapping does not cover becomes its own entry: a thing
    # the firmware declares may not vanish because our table has no row, AND it
    # is what keeps `n` and the entry-id set FUNCTIONS OF THE IMAGE rather than
    # of the MAP literal.  Without it the guard's `n` term is inert.
    for t in sorted(unmapped):
        entries.append({"id": "mapping_gap_%s" % t.replace(":", "_"),
                        "from": [t], "declared_by": [t], "supported": True,
                        "mapping_gap": True,
                        "what": "declared by the firmware and NOT covered by "
                                "MAP -- counted, and a mapping to write"})

    def _eid(e: Dict[str, Any]) -> str:
        return "%s|%s" % (e["id"], "+".join(sorted(e["declared_by"])) or
                          "UNSUPPORTED")
    return {
        "device": "adam6000-tm4c",
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_len": len(image),
        "blocks": bl,
        "declaring_tokens": sorted(have),
        "unmapped_tokens": sorted(unmapped),
        "entry_ids": sorted(_eid(e) for e in entries),
        "entries": entries,
        "substrate": SUBSTRATE,
        "n": len(entries),
        "n_is_a_floor": True,
        "floor_reason": "OTA_tcptls_* and the P2P task are further declared "
                        "links that A1..A6 do not reach; REFERRED, not counted",
        "no_dispatch_table": "this image has no service dispatch table: the "
                             "ASCII decoder is inline character compares and "
                             "the tokens sit in scattered literal pools",
    }


def default_image() -> str:
    """The image THE MACHINE LOADS, resolved the way HALucinator resolves it."""
    try:
        sys.path.insert(0, os.path.join(
            os.path.dirname(os.path.abspath(__file__)), os.pardir, "src"))
        from rehostry_adam6000_tm4c import paths as _paths          # noqa
        cfg = str(_paths.config_paths(False)[0])
        cfgdir = os.path.dirname(cfg)
        want = _paths.FIRMWARE_BIN
        with open(cfg) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("file:") and line.split(":", 1)[1].strip() == want:
                    return os.path.realpath(os.path.join(cfgdir, want))
    except Exception:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.realpath(os.path.join(
        here, os.pardir, "src", "rehostry_adam6000_tm4c", "configs",
        "adam6000_tm4c.bin"))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    path = a.image or default_image()
    with open(path, "rb") as fh:
        image = fh.read()
    out = derive(image)
    if a.json:
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    print("image     %s" % path)
    print("image sha %s  (%d bytes)" % (out["image_sha256"], out["image_len"]))
    for k in sorted(out["blocks"]):
        b = out["blocks"][k]
        print("%s %-22s 0x%05X..0x%05X n=%-2d sha %s"
              % (k, b["name"], b["start"], b["end"], b["count"],
                 b["bytes_sha256"][:16]))
        print("     %s" % ", ".join(b["tokens"]))
    if out["unmapped_tokens"]:
        print("UNMAPPED (counted as mapping_gap entries): %s"
              % ", ".join(out["unmapped_tokens"]))
    print("entries:")
    for e in out["entries"]:
        print("   %-24s %s" % (e["id"], ",".join(e["declared_by"]) or "UNSUPPORTED"))
    print("n = %d  (FLOOR)" % out["n"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
