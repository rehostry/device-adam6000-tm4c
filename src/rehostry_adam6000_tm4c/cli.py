# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`rehostry-adam6000-tm4c` CLI: boot the re-host standalone.

`run` boots the firmware under HALucinator (unicorn) and streams its console /
log output to stdout for `--seconds`, then reaps the whole process tree. With
`--bridge` it also overlays the host bridge, so a real client (or the web panel,
`python3 -m rehostry_adam6000_tm4c.adam6000_panel`) can drive the firmware's own protocol
engine. No orchestrator, no `project.` symlink -- the config's handler classes
import straight from the installed `rehostry_adam6000_tm4c` package.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time

from . import paths, spawn


def _descendants(pid: int) -> list[int]:
    out: list[int] = []
    try:
        kids = subprocess.run(["pgrep", "-P", str(pid)],
                              capture_output=True, text=True).stdout.split()
    except (OSError, ValueError):
        kids = []
    for k in kids:
        out.extend(_descendants(int(k)))
        out.append(int(k))
    return out


def _kill_tree(proc: subprocess.Popen) -> None:
    # Kill ONLY the PIDs we started (via the Popen handle). NEVER `pkill -f
    # halucinator` -- a global pattern kill takes out other sessions' emulators
    # and the victim sees rc=-15 with no fault in the log (playbook trap 10).
    pids = _descendants(proc.pid) + [proc.pid]
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for p in pids:
            try:
                os.kill(p, sig)
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue


def cmd_run(args: argparse.Namespace) -> int:
    if not paths.firmware_present():
        print(f"firmware not found at {paths.firmware_bin()}", file=sys.stderr)
        print("  (regenerate it with tools/extract_firmware.py -- see PROVENANCE.md)",
              file=sys.stderr)
        return 1

    argv = spawn.spawn_argv(emulator=args.emulator, bridge=args.bridge)
    env = spawn.spawn_env()

    print(f"[rehostry-adam6000-tm4c] booting: {' '.join(argv)}")
    print(f"[rehostry-adam6000-tm4c] cwd={spawn.spawn_cwd()}  (configs from the installed package)")
    if args.bridge:
        print(f"[rehostry-adam6000-tm4c] host bridge on tcp/{args.port} "
              f"(drive it with `python3 -m rehostry_adam6000_tm4c.adam6000_panel --port {args.port}`)")

    proc = subprocess.Popen(argv, cwd=spawn.spawn_cwd(), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, preexec_fn=os.setsid)
    deadline = time.monotonic() + args.seconds
    try:
        assert proc.stdout is not None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                for line in proc.stdout:      # drain whatever is left
                    sys.stdout.write(line)
                print("[rehostry-adam6000-tm4c] HALucinator exited early.", file=sys.stderr)
                return proc.returncode or 1
            line = proc.stdout.readline()
            if line:
                sys.stdout.write(line)
            else:
                time.sleep(0.05)
        print(f"[rehostry-adam6000-tm4c] ran for {args.seconds:.0f}s; tearing down.")
        return 0
    finally:
        _kill_tree(proc)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="rehostry-adam6000-tm4c",
        description="Standalone <adam6000-tm4c DESCRIPTION> device for HALucinator.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="boot the firmware and stream its console")
    r.add_argument("--seconds", type=float, default=15.0)
    r.add_argument("--emulator", default="unicorn")
    r.add_argument("--bridge", action="store_true",
                   help="overlay the host bridge (TCP server for a real client)")
    r.add_argument("--port", type=int, default=spawn.BRIDGE_PORT,
                   help="bridge TCP port (default %d)" % spawn.BRIDGE_PORT)
    r.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
