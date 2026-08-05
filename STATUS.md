<!-- Copyright 2026 Christopher Wright; SPDX-License-Identifier: AGPL-3.0-or-later -->
# STATUS — device-adam6000-tm4c  (**M4**)

**Milestone reached: M4 — a Modbus/TCP round-trip.** The vendor image boots its
own bootloader, loads and runs the application, reads its (blank) serial flash,
saves configuration to internal flash, brings up lwIP, **transmits and receives
Ethernet frames**, completes a TCP handshake on port 502, and **answers Modbus
requests from its own Modbus server**:

```
>>> 000100000006 01 01 00000008     read coils 0..7
<<< 000100000003 01 81 02           exception 2, illegal data address

>>> 000100000006 01 41 00000001     function 0x41 -- not a Modbus function
<<< 000100000003 01 c1 01           exception 1, illegal function
```

`src/rehostry_adam6000_tm4c/attack.py` boots one device per probe and checks
18 assertions; all pass:

```
[PASS] answered / exception echoes the function / exception code 2   (fc 01,02,03,05)
[PASS] answered / exception echoes the function / exception code 1   (fc 0x41)
[PASS] a real parser: unsupported and unusable differ
[PASS] every address is illegal, and the device says why
[PASS] the stack is the firmware's own
```

**Why every answer is an exception, and why that is still evidence.** This
module keeps its identity — model number, channel count, the whole I/O profile
— in a serial NOR flash beside the microcontroller, and that flash is not part
of the distributed firmware image. The device boots and says so:

```
 Boot_ SFinit() ff,ff,ff,ff,...
[SIFlashRead_s] profile=ffffffff
 Profi_XX: not found in flash
 GetDevInfo() Err: ulLen=-1
---------------g_sModelInfo.ucTotal_StatusPins = 0
g_usModel = 255
```

A module with no I/O points has no legal data address, so every read is
exception 2. Filling that flash with invented vendor data would produce
prettier output and would be a fabrication.

What makes it evidence anyway is the **discrimination**: a supported function
code aimed at an unusable address is refused as *illegal data address* (2),
while an unsupported function code is refused as *illegal function* (1), with
the function byte echoed and the top bit set in both. Nothing that merely
pretends to be a Modbus server tells those apart.

## The boot, and the network coming up

```
QualComm Project Boot Code Start
 BL: Advantech ADAM-6000D A1.03B10!! 0
6000_DIO V6.15B23 start!!
 ip=100000a, sm=ff, gw=0
MACID:0.d0.c9.fe.ff.ff
[lwIPInit] g_ui32IPMode = 0, g_ui32IPAddr=100000a, ...
IP ready.
```

```
EMAC TX #1: 42 bytes ffffffffffff000000000000080600010800060400010000000000000a000001
             |          |                                              +-- 10.0.0.1
             |          +-- ethertype 0x0806 = ARP, opcode 1 = request
             +-- broadcast
EMAC TX #3: ARP reply to the peer          <- the device answers what it receives
EMAC RX #4: 66 bytes into 0x20011fbc       <- a Modbus request, into the ring
```

`ip=100000a` is 10.0.0.1, Advantech's factory default, and `00:D0:C9` is
Advantech's real OUI — neither is written into the guest by the host.

## The bug that cost the most: two vector tables

The image carries **two** vector tables — the bootloader's at `0x00000000` and
the application's at `0x00010000` — and the application relocates to its own by
writing VTOR. The backend keeps its own copy of the vector base and only learns
about it through `set_vtor()`, so a PPB model that merely stored the register
left every interrupt dispatching through the *bootloader's* table.

That failed in the worst possible way: **both** tables have a live entry for
IRQ 40, so interrupts kept working and kept landing in the bootloader's
Ethernet driver, whose `netif` the application never initialises. Its
`netif->state` was still the `.data` image (`0xFFFFFFFF`), and the receive walk
faulted:

```
64c8: ldr r0, [r0, #28]     ; netif->state  -> 0xFFFFFFFF
64cc: ldr r5, [r0, #8]      ; [0xFFFFFFFF+8] wraps to 0x07 -- inside the vector table
64e2: ldr r0, [r5, #0]      ; UC_ERR_READ_UNMAPPED at 0x00F0BD00
```

`0x00F0BD00` is the unaligned word at offset 7 of the table: the top byte of
the reset vector followed by three bytes of the NMI vector. It reads exactly
like a descriptor-layout bug in the Ethernet driver, and it is a driver that
was never running. Four hypotheses were tested and disproved before a memory
watchpoint and a pointer-chain probe found it.

## Known limits

- **One Modbus exchange per boot.** The device answers the first request after
  boot and does not pick up later ones, on the same connection or a new one.
  Reproduced at SysTick rates of 1500/2000/3000/4000 ROM calls per tick and
  with up to 200 retransmissions, so it is not the clock and not frame loss.
  `run_attack` works around it by booting one device per probe.
- **No I/O points**, for the serial-flash reason above.
- The web panel renders device state as JSON rather than a coil grid.

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
