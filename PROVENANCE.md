<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Provenance — adam6000-tm4c firmware

<!-- TEMPLATE: record where the firmware came from, how to regenerate it, the
     STATIC falsifiable prediction you derived before the first boot, and the
     licensing. -->

## The binary

- **Upstream / corpus:** TODO — which benchmark or corpus, with a URL. (The
  repo's default corpus is `uEmu-real_world_firmware`; device-plc uses P2IM.)
- **Target:** TODO — MCU / core / RTOS or bare-metal, and what the firmware does.
- **Build origin:** TODO — any toolchain / debug-path evidence from the ELF.
- **Hashes** (of the extracted binaries):
  - `adam6000_tm4c.bin`  sha256 `TODO` (`<n>` bytes)
  - `adam6000_tm4c.elf`  sha256 `TODO`

## How the target was identified

TODO: how you resolved the MCU/peripheral bases and the vector table (init_SP,
Reset_Handler), and how `tools/extract_firmware.py` re-derives + guards them.

## The falsifiable prediction

<!-- The single most valuable artifact (playbook §3). Derive it STATICALLY,
     BEFORE the first boot: disassemble the transmit/response path, work out
     exactly what bytes the firmware MUST emit, write it here, THEN boot. If the
     running firmware produces those bytes, the match cannot be circular -- the
     host has no code that could have synthesised them. -->

TODO: the exact bytes/registers the firmware must emit, disassembled from the
transmit path, with the addresses of the functions involved — recorded before
the run.

## Licensing

This re-host package is **AGPL-3.0-or-later**.

TODO: state whether the firmware binaries are **committed** here. By default they
are NOT (`.gitignore` excludes `*.bin`/`*.elf`; regenerate with
`tools/extract_firmware.py`). Commit them ONLY if every constituent part is
redistributable — then list each part, its role, its upstream, and its licence
in a table (see device-plc/PROVENANCE.md), and reproduce the licence texts under
`licenses/`.
