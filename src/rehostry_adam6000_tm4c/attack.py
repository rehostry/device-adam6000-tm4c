# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The adam6000-tm4c attack scenario, driven against the firmware's OWN engine.

TEMPLATE -- this file implements the fleet-standard attack contract (playbook
2a). Keep the SHAPE; replace the oracle. See device-plc/attack.py (an
unauthenticated Modbus write proven by read-back) and
device-zephyr-can/attack.py (a spoofed CAN frame proven by the firmware's own
hexdump) for worked examples.

Four hard requirements (playbook 2a):
  1. `run_attack(on_stage=None, log_dir=None) -> dict` returning at least
     {"booted": bool, "landed": bool}.
  2. Exactly ONE final line `RESULT: {json}` carrying at least those two keys.
  3. Self-booting: `python -m rehostry_adam6000_tm4c.attack` must work with nothing
     running beforehand -- it spawns its own rehost and tears down ONLY the PIDs
     it started.
  4. The oracle is the FIRMWARE'S OWN output. Never set `landed: true` from host
     bookkeeping; never weaken a check to make a run pass. If it does not land,
     `RESULT:` must say `"landed": false`.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Callable, Dict, List, Optional

from . import paths, spawn

# TODO: describe the attack's target(s) in the firmware's own state, and any
# labelled baseline you seed so the read/attack is legible (see device-plc's
# PROCESS_IMAGE).


class DeviceScenario:
    """Boots the adam6000-tm4c firmware (+ its host bridge, if any) as an emulator
    subprocess and drives the read + the attack. The firmware is the real rehost;
    only any seeded baseline is illustrative."""

    def __init__(self, bridge_port: int = spawn.BRIDGE_PORT,
                 python: Optional[str] = None, log_dir: Optional[str] = None) -> None:
        self.bridge_port = bridge_port
        self.python = python or sys.executable
        self.log_dir = log_dir or "/tmp"
        self.host = "127.0.0.1"
        self._procs: List[subprocess.Popen] = []
        self.log = os.path.join(self.log_dir, "adam6000-tm4c_attack.log")

    # ---- process management ------------------------------------------------
    def _spawn(self, argv, cwd, env, logpath) -> subprocess.Popen:
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=open(logpath, "w"),
                             stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        self._procs.append(p)
        return p

    @staticmethod
    def _log_has(logpath, needle) -> bool:
        try:
            return needle in open(logpath, errors="replace").read()
        except OSError:
            return False

    def boot(self, on_stage: Callable) -> bool:
        """Boot the firmware under HALucinator (+ bridge overlay), wait for the
        readiness marker, then seed any illustrative baseline."""
        if not paths.firmware_present():
            on_stage("error", note="firmware not found at %s" % paths.firmware_bin())
            return False
        argv = spawn.spawn_argv(python=self.python, emulator="unicorn", bridge=True)
        env = spawn.spawn_env(extra={"PYTHONUNBUFFERED": "1"})
        cwd = spawn.spawn_cwd()
        on_stage("boot", note="booting adam6000-tm4c firmware ...")
        p = self._spawn(argv, cwd, env, self.log)

        # TODO: replace "LISTENing on tcp/%d" with YOUR readiness marker -- the
        # host bridge's LISTEN line, or a firmware-emitted driver string that
        # proves M2. Poll the log (and check p.poll() for an early exit) rather
        # than sleeping a fixed time. macOS has no timeout(1) -- bound from here.
        deadline = time.time() + 300
        while time.time() < deadline:
            if p.poll() is not None:
                on_stage("error", note="HALucinator exited during boot (see %s)" % self.log)
                return False
            if self._log_has(self.log, "LISTENing on tcp/%d" % self.bridge_port):
                break
            time.sleep(2)
        else:
            on_stage("error", note="firmware never reached the readiness marker")
            return False

        # TODO: seed any labelled baseline into firmware state here.
        on_stage("ready", note="firmware up")
        return True

    def shutdown(self) -> None:
        # Kill ONLY the PIDs we started. NEVER a global pattern kill (trap 10).
        for p in self._procs:
            try:
                os.killpg(os.getpgid(p.pid), 15)
            except Exception:  # noqa: BLE001
                pass
        self._procs = []

    # ---- read / attack seams -----------------------------------------------
    def read_state(self) -> Dict[str, object]:
        """Read the firmware's real state (ground truth, before the attack).

        TODO: read the firmware's OWN state through its real engine (its protocol
        response, a register file, a driver seam). This is the pre-attack
        baseline the oracle compares against.
        """
        raise NotImplementedError("TODO: read the firmware's own state")

    def attack(self) -> dict:
        """Run the attack against the firmware's own engine and verify from the
        firmware's OWN output.

        TODO: perform the attack, then confirm it with an INDEPENDENT read of the
        firmware's own state. `landed` is true iff the firmware's own output
        shows the attacker's effect -- never from host bookkeeping.
        """
        raise NotImplementedError("TODO: run the attack and verify from firmware evidence")


def run_attack(on_stage: Optional[Callable] = None,
               log_dir: Optional[str] = None) -> dict:
    """Fleet-standard entry point (playbook 2a): boot the firmware, read the
    baseline, run the attack, verify from firmware-side evidence. Self-booting.

    Returns a dict with at least ``booted`` and ``landed``. ``landed`` comes from
    the firmware's OWN output, never from host bookkeeping.
    """
    def stage(name, **d):
        if on_stage:
            on_stage(name, **d)

    sc = DeviceScenario(python=sys.executable, log_dir=log_dir or "/tmp")
    result: dict = {"booted": False, "landed": False}
    try:
        if not sc.boot(stage):
            return result
        result["booted"] = True
        state = sc.read_state()
        stage("read", state=state)
        atk = sc.attack()
        stage("attack", result=atk)
        result["state"] = state
        result["attack"] = atk
        result["landed"] = bool(atk.get("landed"))
    finally:
        sc.shutdown()
    return result


def main() -> int:
    import json

    def show(name, **data):
        note = data.get("note", "")
        if note:
            print(f"[stage] {name}: {note}")
        else:
            print(f"[stage] {name}")

    res = run_attack(on_stage=show)
    # Exactly one RESULT line, parseable JSON, with at least booted + landed.
    print("RESULT:", json.dumps({k: v for k, v in res.items()
                                 if k in ("booted", "landed")}))
    return 0 if res.get("landed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
