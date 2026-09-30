#!/usr/bin/env python3
# Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later
"""Pre-registration guard for the derived inventory.  Mismatch VOIDS parity.

``INVENTORY-PREREG.json`` is committed BEFORE any graded arm.  Every graded run
re-derives the inventory from the image the machine loads and compares it.  A
mismatch **in either direction** VOIDS the parity fraction; a voided run
publishes no number.

Two guard-design lessons this is built around:

1. **Compare SETS, not sizes.**  Two sibling rows derived the same ``n`` from
   different images; a size-only guard would have accepted one row's
   pre-registration against the other's bytes.  ``n`` is checked, and so is the
   token SET of each declaring block, and so is the entry-id SET, symmetrically.
2. **An id-only guard can be INERT.**  So the **raw bytes** of each declaring
   block are pinned (``bytes_sha256``) alongside its derived extent.
   ``--falsify flip-inner-byte`` demonstrates it: it changes a byte that leaves
   every token and every entry id intact, and the guard still VOIDs.

⚠ ``--falsify-all`` prints **every** term that fired, and names the terms that no
arm moved.  A term no arm can move is not a measurement, and an arm that always
trips the same first term teaches nothing about the rest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import derive_inventory as di            # noqa: E402

PREREG = os.path.join(_HERE, os.pardir, "INVENTORY-PREREG.json")
TERMS = ("image_sha256", "block_extent", "block_tokens_extra",
         "block_tokens_missing", "block_bytes_sha256", "entry_ids_extra",
         "entry_ids_missing", "n")


def check(derived: Dict[str, Any], prereg: Dict[str, Any]) -> Dict[str, Any]:
    why: List[str] = []
    # Every key the guard reads must be PRESENT.  A .get() yielding None on an
    # absent key turns a tool defect into a false accusation, so absence raises.
    for k in ("image_sha256", "entry_ids", "n", "blocks"):
        if k not in derived:
            raise KeyError("derived inventory has no %r -- Undetermined" % k)
        if k not in prereg:
            raise KeyError("pre-registration has no %r -- Undetermined" % k)
    if derived["image_sha256"] != prereg["image_sha256"]:
        why.append("image_sha256: %s != pre-registered %s"
                   % (derived["image_sha256"][:16], prereg["image_sha256"][:16]))
    for bk in sorted(set(derived["blocks"]) | set(prereg["blocks"])):
        if bk not in derived["blocks"] or bk not in prereg["blocks"]:
            why.append("block_extent: block %s present on one side only" % bk)
            continue
        d, p = derived["blocks"][bk], prereg["blocks"][bk]
        for f in ("start", "end", "count", "bytes_sha256", "tokens"):
            if f not in d or f not in p:
                raise KeyError("block %s has no %r -- Undetermined" % (bk, f))
        if (d["start"], d["end"]) != (p["start"], p["end"]):
            why.append("block_extent: %s 0x%X..0x%X != pre-registered 0x%X..0x%X"
                       % (bk, d["start"], d["end"], p["start"], p["end"]))
        if d["count"] != p["count"]:
            why.append("block_extent: %s count %d != pre-registered %d"
                       % (bk, d["count"], p["count"]))
        dt, pt = set(d["tokens"]), set(p["tokens"])
        if dt - pt:
            why.append("block_tokens_extra: %s declares %s, not pre-registered"
                       % (bk, ",".join(sorted(dt - pt))))
        if pt - dt:
            why.append("block_tokens_missing: %s pre-registered %s, absent now"
                       % (bk, ",".join(sorted(pt - dt))))
        if d["bytes_sha256"] != p["bytes_sha256"]:
            why.append("block_bytes_sha256: %s RAW BYTES %s != pre-registered %s"
                       % (bk, d["bytes_sha256"][:16], p["bytes_sha256"][:16]))
    d_ids, p_ids = set(derived["entry_ids"]), set(prereg["entry_ids"])
    if d_ids - p_ids:
        why.append("entry_ids_extra: %s" % ",".join(sorted(d_ids - p_ids)))
    if p_ids - d_ids:
        why.append("entry_ids_missing: %s" % ",".join(sorted(p_ids - d_ids)))
    if derived["n"] != prereg["n"]:
        why.append("n: %d != pre-registered %d" % (derived["n"], prereg["n"]))
    return {"ok": not why, "void_reasons": why,
            "terms_fired": sorted(set(w.split(":", 1)[0] for w in why)),
            "n": derived["n"], "entry_ids": sorted(d_ids),
            "image_sha256": derived["image_sha256"],
            "block_shas": {k: v["bytes_sha256"]
                           for k, v in derived["blocks"].items()},
            "declaring_tokens": derived.get("declaring_tokens"),
            "unmapped_tokens": derived.get("unmapped_tokens"),
            "prereg_path": os.path.relpath(PREREG, os.path.dirname(_HERE)),
            "prereg_sha256": prereg.get("_self_sha256"),
            "_provenance": {
                "image_sha256": "sha256 of the bytes THIS PROCESS read from the "
                                "image named by the config spawn hands to "
                                "halucinator.main",
                "block_extent": "derive_inventory.block_tasks/block_modules -- "
                                "walked from the firmware's OWN symbol string",
                "block_tokens_*": "the names parsed out of those blocks",
                "block_bytes_sha256": "sha256 of the raw declaring-block bytes",
                "entry_ids_*": "symmetric set difference against the "
                               "pre-registration",
                "n": "len(MAP) entries supported by those tokens or carried "
                     "forward"}}


def run(image_path: Optional[str] = None, prereg_path: Optional[str] = None,
        falsify: Optional[str] = None) -> Dict[str, Any]:
    path = image_path or di.default_image()
    with open(path, "rb") as fh:
        image = fh.read()
    if falsify:
        image = _perturb(bytearray(image), falsify)
    with open(prereg_path or PREREG) as fh:
        raw = fh.read()
    prereg = json.loads(raw)
    prereg["_self_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    out = check(di.derive(image), prereg)
    out["falsify"] = falsify
    out["image_path"] = path
    out["image_sha256_loaded"] = hashlib.sha256(image).hexdigest()
    return out


def _perturb(buf: bytearray, mode: str) -> bytes:
    """Mutate a COPY of the image.  Never writes to disk."""
    if mode == "flip-inner-byte":
        # A byte inside A1 that is part of NO key: the trailing '}'.  Every token
        # and every entry id survives; only the raw-byte pin can catch it.
        off = buf.find(b'{"DSport":')
        end = buf.find(b"\x00", off)
        buf[end - 1] = ord("]")
    elif mode == "rename-a1-key":
        off = buf.find(b'"MBport"')
        buf[off + 1] = ord("Z")
    elif mode == "break-a1-uniqueness":
        # Turn a second run into an A1 candidate: the deriver must REFUSE rather
        # than pick one, and a refusal is a void, not a pass.
        off = buf.find(b'{"status":0}')
        buf[off:off + 12] = b'{"Xport":%d}'
    elif mode == "rename-a6-token":
        off = buf.find(b"ETWEBSRV\x00")
        buf[off] = ord("S")
    elif mode == "drop-a6-cr-token":
        off = buf.find(b"LSMBTCP\r")
        buf[off] = ord("X")
    elif mode == "rename-a5-community":
        off = buf.find(b"ucTrapCommunity")
        buf[off + 2] = ord("X")
    elif mode == "rename-a3-field":
        off = buf.find(b"ucEnAzureIoTHub")
        buf[off + 4] = ord("X")
    elif mode == "image-byte":
        # Far outside every block: the image term must fire ALONE, which is how
        # these arms show the block terms are not merely shadowed by it.
        buf[len(buf) - 1] ^= 0xFF
    else:
        raise SystemExit("unknown falsify mode %r" % mode)
    return bytes(buf)


FALSIFY_MODES = ("flip-inner-byte", "rename-a1-key", "break-a1-uniqueness",
                 "rename-a6-token", "drop-a6-cr-token", "rename-a5-community",
                 "rename-a3-field", "image-byte")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", default=None)
    ap.add_argument("--prereg", default=None)
    ap.add_argument("--falsify", choices=FALSIFY_MODES, default=None)
    ap.add_argument("--falsify-all", action="store_true")
    ap.add_argument("--emit-prereg", action="store_true")
    a = ap.parse_args(argv)

    if a.emit_prereg:
        path = a.image or di.default_image()
        with open(path, "rb") as fh:
            d = di.derive(fh.read())
        json.dump({"_comment": "PRE-REGISTERED inventory. Committed before any "
                               "graded arm. A graded run that derives anything "
                               "else VOIDS its parity fraction.",
                   "device": d["device"],
                   "image_sha256": d["image_sha256"],
                   "image_len": d["image_len"],
                   "blocks": {k: {f: v[f] for f in
                                  ("name", "start", "end", "count", "tokens",
                                   "predicate", "bytes_sha256", "bytes_len")}
                              for k, v in d["blocks"].items()},
                   "declaring_tokens": d["declaring_tokens"],
                   "entry_ids": d["entry_ids"],
                   "n": d["n"],
                   "n_is_a_floor": d["n_is_a_floor"],
                   "floor_reason": d["floor_reason"]},
                  sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if a.falsify_all:
        bad, seen = [], set()
        base = run(a.image, a.prereg)
        print("control (unperturbed): ok=%s n=%s" % (base["ok"], base["n"]))
        for w in base["void_reasons"]:
            print("      VOID: %s" % w)
        if not base["ok"]:
            bad.append("control")
        for m in FALSIFY_MODES:
            try:
                o = run(a.image, a.prereg, falsify=m)
            except SystemExit as exc:
                # The deriver refusing to derive is ALSO a void, and an honest
                # one -- report it as such rather than as a pass.
                print("falsify %-20s ok=False (deriver refused: %s)" % (m, exc))
                seen.add("deriver_refused")
                continue
            seen |= set(o["terms_fired"])
            print("falsify %-20s ok=%-5s  ids-unchanged=%-5s  terms=%s"
                  % (m, o["ok"],
                     set(o["entry_ids"]) == set(base["entry_ids"]),
                     ",".join(o["terms_fired"]) or "NONE"))
            for w in o["void_reasons"]:
                print("      %s" % w)
            if o["ok"]:
                bad.append(m)
        dead = [t for t in TERMS if t not in seen]
        print("\nterms exercised by >=1 arm: %s" % ",".join(sorted(seen)))
        print("terms NO arm moved:        %s" % (",".join(dead) or "none"))
        print("GUARD %s" % ("BITES on every mode" if not bad
                            else "INERT on: %s" % ",".join(bad)))
        return 1 if bad else 0

    o = run(a.image, a.prereg, a.falsify)
    json.dump(o, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if o["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
