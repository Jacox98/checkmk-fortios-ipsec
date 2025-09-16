"""Agent-based plugin for FortiGate IPsec tunnel monitoring."""

from __future__ import annotations

from typing import Dict, Iterable, List

from cmk.agent_based.v1 import Result, Service, State, register

Section = List[Dict[str, str]]


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


def discover_fortigate_ipsec(section: Section) -> Iterable[Service]:
    if section and section[0].get("error"):
        return
    for tunnel in section:
        name = tunnel.get("name")
        if name:
            yield Service(item=name)


def check_fortigate_ipsec(item: str, section: Section) -> Iterable[Result]:
    if section and section[0].get("error"):
        yield Result(state=State.CRIT, summary=f"Tunnel data unavailable: {section[0]['error']}")
        return

    for tunnel in section:
        if tunnel.get("name") != item:
            continue
        status = (tunnel.get("status") or "").lower()
        is_up = status == "up"
        state = State.OK if is_up else State.CRIT
        summary = f"Tunnel {item} is {'up' if is_up else 'down'}"
        yield Result(state=state, summary=summary)
        details = ", ".join(
            [
                f"Local GW: {tunnel.get('local_gw') or '-'}",
                f"Remote GW: {tunnel.get('remote_gw') or '-'}",
                f"RX: {tunnel.get('rx_bytes') or '0'} B",
                f"TX: {tunnel.get('tx_bytes') or '0'} B",
            ]
        )
        yield Result(state=State.OK, notice=details)
        return


register.agent_section(
    name="fortigate_ipsec",
    parse_function=parse_fortigate_ipsec,
)

register.check_plugin(
    name="fortigate_ipsec",
    service_name="FortiGate IPsec %s",
    discovery_function=discover_fortigate_ipsec,
    check_function=check_fortigate_ipsec,
)