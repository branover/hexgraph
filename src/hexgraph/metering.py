"""The Metering seam (v2 P0-3).

Records resource usage per task/feature. In the BYOK build the user spends against
their own provider key, so the local sink only logs. This is where a future
HexGraph-credits sink reports metered usage to a HexGraph account for paid
features — without touching task code.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from hexgraph.principal import Principal, current_principal

log = logging.getLogger("hexgraph.metering")


class MeteringSink(Protocol):
    def record(self, *, feature: str, principal_id: str, task_id: str | None, usage: Any) -> None: ...


class LocalLogMeteringSink:
    name = "local"

    def record(self, *, feature: str, principal_id: str, task_id: str | None, usage: Any) -> None:
        log.debug("metering feature=%s principal=%s task=%s usage=%s", feature, principal_id, task_id, usage)


_sink: MeteringSink | None = None


def current_metering() -> MeteringSink:
    global _sink
    if _sink is None:
        _sink = LocalLogMeteringSink()
    return _sink


def record_usage(feature: str, usage: Any, *, task_id: str | None = None, principal: Principal | None = None) -> None:
    p = principal or current_principal()
    current_metering().record(feature=feature, principal_id=p.id, task_id=task_id, usage=usage)
