# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device breakpoint handlers.

TODO: add BPHandler subclasses here to intercept firmware functions (a host
bridge, a busy-wait breaker, a driver-seam answer). A handler is referenced from
the config's ``intercepts:`` block by its installed dotted path
(``rehostry_adam6000_tm4c.bp_handlers.<mod>.<Class>``). See
device-plc/bp_handlers/modbus_uart_bridge.py for a full host-bridge example.

Gotchas (playbook):
  * The ``function:`` in an intercept must match a name in ``@bp_handler([...])``,
    NOT the Python method name. Convention: make them identical to the symbol
    (trap 2).
  * Use ``from halucinator import hal_log; log = hal_log.getHalLogger()`` for any
    log visibility (trap 1).
  * If a handler starts a TCP server, bind SYNCHRONOUSLY at ``register_handler``
    time (before unicorn's emu_start holds the GIL), and only ONCE via a class
    flag -- see ModbusUartBridge.register_handler (trap 3, 12).
"""
