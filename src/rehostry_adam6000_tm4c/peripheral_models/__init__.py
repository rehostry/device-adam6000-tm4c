# Copyright 2026 Christopher Wright
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Device peripheral models.

TODO: add MMIO register models here for any peripheral the firmware polls whose
default-0 read flips a branch you care about. A model subclasses
``halucinator.peripheral_models.auto_model.AutoPeripheral`` and is referenced
from the config's ``peripherals:`` block by its installed dotted path
(``rehostry_adam6000_tm4c.peripheral_models.<mod>.<Class>``).

Gotchas (playbook):
  * Use ``from halucinator import hal_log; log = hal_log.getHalLogger()`` -- a
    plain ``logging.getLogger(__name__)`` is silent (trap 1/2).
  * Models are constructed MORE THAN ONCE while a config resolves. Never bind a
    socket or start a thread naively in ``__init__``: use a module-level
    singleton + a ``get_bus()``-style accessor (trap 3, 12).
  * Prefer register-level capture over intercepting a driver's send function --
    the register file is the real bus boundary (see device-zephyr-can's bxcan.py).
  * NAMING the class ``AutoPeripheral`` sets a GLOBAL ``skip_svc`` flag that
    breaks FreeRTOS/NuttX/Zephyr's task-starting ``svc``. If you need the
    catch-all's behaviour but also need SVC, subclass it under a DIFFERENT name
    (e.g. ``AbsorbingPeripheral`` -- see device-nuttx-fs/soc_catchall.py) (trap 11).
"""
