<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — device-adam6000-tm4c  (WIP: **M1**, not published)

**Milestone reached: M1.** The vendor image boots, runs ARM Compiler's
scatter-load/zero-init startup to completion (20,259 passes of the zero-init
loop), and configures the clock tree — then takes an exception and spins in the
shared default handler at `0x0000F0C0`.

This is unfinished work, recorded so the next session does not repeat it.

## What is established (and checked by `tools/extract_firmware.py`)

**The SoC was identified from the image alone.** There is no part number in it:

- GPIO ports **A through Q** are addressed (`0x40061000`..`0x40066000` = K/L/M/
  N/P/Q). Only the TM4C129x family has ports past J.
- **EMAC0 at `0x400EC000`** — an on-chip Ethernet MAC, which in the Tiva line
  exists only on the Connected (129x) series.
- Of 112 external interrupt slots, **exactly one is live: IRQ 40**, which is
  TM4C129x's EMAC0. The extractor pins that as the device's fingerprint.
- `SYSCTL` at `0x400FE000`, and the registers the firmware drives are TM4C129x's
  by offset: `RSCLKCFG` (0x0B0), `PLLFREQ0` (0x160, bit 23 = PLLPWR),
  `PLLSTAT` (0x168, bit 0 = LOCK).
- The image contains the literal string `Cortex-M4` and TivaWare's Hungarian
  notation (`g_ui32IPMode`) throughout its debug output.

**The software stack**, from its own strings: bare-metal TivaWare (no RTOS —
there is no FreeRTOS string anywhere) + lwIP + an HTTP server with an embedded
web UI + Modbus/TCP + SNMP + mbedTLS 3.6.0 + an Azure IoT client. The vendor's
own build path survives: `D:\ADAM-6000DIO_V615\Code\Lib\mbedtls-3.6.0\...`.

## The gates, in the order they will be met

1. **SYSCTL / PLL.** `PLLSTAT.LOCK` is polled with a timeout at `0x0000B036`.
   Currently answered by the catch-all's busy-wait breaker, which happens to
   work; it wants a real model.
2. **The TM4C masked ROM — the one that changes the shape of this device.**
   The firmware calls TivaWare driverlib through the on-chip **ROM API table at
   `0x01000010`**, and there is no ROM image to supply: the table lives in
   masked ROM on real silicon. At `0x00006EAC` it does
   `r4 = 0x01000014; r1 = [r4+0x30]; r1 = [r1+0x18]; blx r1` — a two-level
   dispatch through that table. Left unmapped this aborts the run outright;
   mapped as a probe region, **exactly one table entry is fetched so far**
   (`0x01000044`), which suggests the dependency may be small enough to
   synthesise rather than emulate wholesale.
   The approach that fits: map `0x01000000` as a model that returns *synthesised*
   pointers into a stub region, log which table index each call fetches, and
   implement only the entries the firmware actually uses as bp_handlers. The
   call sites identify themselves — the one above sits next to `0x4000C000`
   (UART0), so it is a UART routine.
3. **The current stall.** After startup the CPU vectors to `0x0000F0C0`, which
   is the *shared* default handler for MemManage/BusFault/UsageFault/SVCall/
   DebugMon/PendSV — and is a `b .` spin. It is **not** HardFault (that vector
   is `0x0000F0BE`), nothing in the image branches there, and the literal
   `0x0000F0C1` appears only in the vector table, so it is a genuine exception
   entry. Two hypotheses tested and **both wrong**: it is not an unmapped access
   (none is logged), and it is not SVCall (forcing the core's `skip_svc` changes
   nothing). Next step is to read `CFSR`/`HFSR` at the moment of entry — model
   the PPB and log the fault status registers rather than guessing again.
4. **EMAC0 + descriptors**, then lwIP, then a host-side ARP/IP/TCP peer to carry
   Modbus/TCP for M4. The 802.15.4 peer in `device-openthread-nrf52840` is the
   shape to copy, one layer up the stack.

## Honest scope note

This device is materially larger than the three before it: it needs a
synthesised TivaWare ROM layer, a clock tree, an Ethernet MAC with DMA
descriptors, and a host-side TCP peer before a Modbus/TCP round-trip is
possible. M1 is real and the groundwork is verified, but M4 is a session of its
own. Nothing here is published — the repo is local until it earns a milestone
worth shipping.
