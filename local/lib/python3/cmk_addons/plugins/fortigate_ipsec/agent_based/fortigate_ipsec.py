"""Agent-based plugin for FortiGate IPsec tunnel monitoring."""

from __future__ import annotations

from time import time
from typing import Dict, Iterable, List

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    DiscoveryResult,
    GetRateError,
    Metric,
    Result,
    Service,
    State,
    get_rate,
    get_value_store,
)

Section = List[Dict[str, str]]


def _parse_float(value: str | None) -> float:
    try:
        return float(value) if value is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def parse_fortigate_ipsec(string_table: List[List[str]]) -> Section:
    section: Section = []
    for row in string_table:
        if not row:
            continue
        cell = row[0]
        if cell.startswith("ERROR"):
            message = cell.partition(" ")[2] or cell
            return [{"error": message}]
        parts = cell.split(";")
        if len(parts) < 6:
            continue
        name, status, local_gw, remote_gw, rx_bytes, tx_bytes = parts[:6]
        section.append(
            {
                "name": name,
                "status": status,
                "local_gw": local_gw,
                "remote_gw": remote_gw,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
            }
        )
    return section


def discover_fortigate_ipsec(section: Section) -> DiscoveryResult:
    if section and section[0].get("error"):
        return
    for tunnel in section:
        name = tunnel.get("name")
        if name:
            yield Service(item=name)


def check_fortigate_ipsec(item: str, section: Section) -> Iterable[Result | Metric]:
    if section and section[0].get("error"):
        yield Result(state=State.CRIT, summary=f"Tunnel data unavailable: {section[0]['error']}")
        return

    value_store = get_value_store()
    now = time()

    for tunnel in section:
        if tunnel.get("name") != item:
            continue
        status = (tunnel.get("status") or "").lower()
        is_up = status == "up"
        state = State.OK if is_up else State.CRIT
        details = ", ".join(
            [
                f"Local GW: {tunnel.get('local_gw') or '-'}",
                f"Remote GW: {tunnel.get('remote_gw') or '-'}",
                f"RX: {tunnel.get('rx_bytes') or '0'} B",
                f"TX: {tunnel.get('tx_bytes') or '0'} B",
            ]
        )
        summary = f"Tunnel {item} is {'up' if is_up else 'down'} - {details}"
        yield Result(state=state, summary=summary)

        rx_total = _parse_float(tunnel.get("rx_bytes"))
        tx_total = _parse_float(tunnel.get("tx_bytes"))
        for suffix, total, metric_name in (
            ("rx", rx_total, "fortigate_ipsec_rx_bandwidth"),
            ("tx", tx_total, "fortigate_ipsec_tx_bandwidth"),
        ):
            try:
                rate = get_rate(value_store, f"{item}.{suffix}", now, total, raise_overflow=True)
            except GetRateError:
                continue
            yield Metric(metric_name, rate, boundaries=(0.0, None))
        return


agent_section_fortigate_ipsec = AgentSection(
    name="fortigate_ipsec",
    parse_function=parse_fortigate_ipsec,
)


check_plugin_fortigate_ipsec = CheckPlugin(
    name="fortigate_ipsec",
    service_name="FortiGate IPsec %s",
    discovery_function=discover_fortigate_ipsec,
    check_function=check_fortigate_ipsec,
)
