"""Agent-based plugin for FortiGate IPsec tunnel monitoring."""

from __future__ import annotations

import json
from time import time
from typing import Any, Dict, Iterable, List

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
    render,
)

Section = List[Dict[str, Any]]


def _parse_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if value in (None, ""):
        return None
    try:
        return int(str(value), 10)
    except (TypeError, ValueError):
        try:
            return int(float(str(value)))
        except (TypeError, ValueError):
            return None


def _format_endpoint(endpoint: Dict[str, Any]) -> str:
    subnet = endpoint.get("subnet") or "-"
    parts: List[str] = [str(subnet)]
    protocol = endpoint.get("protocol_name") or endpoint.get("protocol")
    port = endpoint.get("port")
    extras: List[str] = []
    if protocol:
        extras.append(str(protocol))
    if port not in (None, ""):
        extras.append(f"port {port}")
    if extras:
        parts.append(f"({', '.join(extras)})")
    return " ".join(parts)


def _parse_legacy_row(cell: str) -> Dict[str, Any] | None:
    parts = cell.split(";")
    if len(parts) < 6:
        return None
    name, status, local_gw, remote_gw, rx_bytes, tx_bytes = parts[:6]
    return {
        "name": name,
        "status": status,
        "local_gateway": local_gw,
        "remote_gateway": remote_gw,
        "incoming_bytes": _safe_int(rx_bytes),
        "outgoing_bytes": _safe_int(tx_bytes),
        "proxies": [],
    }


def parse_fortigate_ipsec(string_table: List[List[str]]) -> Section:
    section: Section = []
    for row in string_table:
        if not row:
            continue
        cell = row[0]
        if cell.startswith("ERROR"):
            message = cell.partition(" ")[2] or cell
            return [{"error": message}]
        try:
            tunnel = json.loads(cell)
        except json.JSONDecodeError:
            legacy = _parse_legacy_row(cell)
            if legacy:
                section.append(legacy)
            continue
        else:
            if isinstance(tunnel, dict):
                section.append(tunnel)
    return section


def discover_fortigate_ipsec(section: Section) -> DiscoveryResult:
    if section and section[0].get("error"):
        return
    for tunnel in section:
        name = tunnel.get("name")
        if name:
            yield Service(item=name)


def _summarize_status(tunnel: Dict[str, Any]) -> tuple[State, str, int, int, int]:
    status = str(tunnel.get("status") or "").strip().lower()
    proxies = tunnel.get("proxies") or []
    total = len(proxies)
    up = 0
    down = 0
    for proxy in proxies:
        proxy_status = str(proxy.get("status") or "").strip().lower()
        if proxy_status == "up":
            up += 1
        elif proxy_status == "down":
            down += 1
    if not status:
        if total:
            if up and not down:
                status = "up"
            elif not up and down:
                status = "down"
            elif up and down:
                status = "mixed"
            else:
                status = "unknown"
        else:
            status = "unknown"
    state_map = {
        "up": State.OK,
        "mixed": State.WARN,
        "down": State.CRIT,
    }
    state = state_map.get(status, State.UNKNOWN)
    if state is State.UNKNOWN and total:
        if up and not down:
            state = State.OK
        elif not up and down:
            state = State.CRIT
        elif up and down:
            state = State.WARN
    return state, status, up, down, total


def _format_bytes(value: float) -> str:
    return render.bytes(int(value))


def _format_bandwidth(total_rx: float, total_tx: float) -> str | None:
    traffic_parts: List[str] = []
    if total_rx > 0:
        traffic_parts.append(f"RX {_format_bytes(total_rx)}")
    if total_tx > 0:
        traffic_parts.append(f"TX {_format_bytes(total_tx)}")
    if not traffic_parts:
        return None
    return "Traffic: " + ", ".join(traffic_parts)


def check_fortigate_ipsec(item: str, section: Section) -> Iterable[Result | Metric]:
    if section and section[0].get("error"):
        yield Result(state=State.CRIT, summary=f"Tunnel data unavailable: {section[0]['error']}")
        return

    value_store = get_value_store()
    now = time()

    for tunnel in section:
        if tunnel.get("name") != item:
            continue

        state, status_text, up, down, total = _summarize_status(tunnel)
        status_display = status_text.upper() or "UNKNOWN"
        if total:
            status_display = f"{status_display} ({up}/{total} phase2 up)"

        remote_gw = tunnel.get("remote_gateway") or tunnel.get("remote_gw") or tunnel.get("rgwy") or "-"
        local_gw = tunnel.get("local_gateway") or tunnel.get("local_gw") or tunnel.get("lgwy") or "-"
        connection_count = tunnel.get("connection_count")
        remote_port = tunnel.get("remote_port") or tunnel.get("rport")
        tunnel_type = tunnel.get("type") or tunnel.get("wizard_type")

        rx_total = _parse_float(tunnel.get("incoming_bytes") or tunnel.get("rx_bytes"))
        tx_total = _parse_float(tunnel.get("outgoing_bytes") or tunnel.get("tx_bytes"))

        summary_fields: List[str] = [f"Status: {status_display}"]
        if remote_gw and remote_gw != "-":
            summary_fields.append(f"Remote: {remote_gw}")
        if local_gw and local_gw != "-":
            summary_fields.append(f"Local: {local_gw}")
        if connection_count not in (None, ""):
            summary_fields.append(f"Connections: {connection_count}")
        if tunnel_type:
            summary_fields.append(f"Type: {tunnel_type}")
        if remote_port not in (None, ""):
            summary_fields.append(f"Port: {remote_port}")
        bandwidth_line = _format_bandwidth(rx_total, tx_total)
        if bandwidth_line:
            summary_fields.append(bandwidth_line)

        yield Result(state=state, summary="; ".join(summary_fields))

        for proxy in tunnel.get("proxies") or []:
            proxy_status_text = str(proxy.get("status") or "").strip().upper() or "UNKNOWN"
            p_name = proxy.get("p2name") or "Phase2"
            src = ", ".join(_format_endpoint(entry) for entry in proxy.get("proxy_src") or []) or "-"
            dst = ", ".join(_format_endpoint(entry) for entry in proxy.get("proxy_dst") or []) or "-"
            detail_fields = [f"{p_name}: {proxy_status_text}", f"Selectors: {src} -> {dst}"]
            proxy_rx = _parse_float(proxy.get("incoming_bytes") or proxy.get("rx_bytes"))
            proxy_tx = _parse_float(proxy.get("outgoing_bytes") or proxy.get("tx_bytes"))
            proxy_bandwidth = _format_bandwidth(proxy_rx, proxy_tx)
            if proxy_bandwidth:
                detail_fields.append(proxy_bandwidth)
            yield Result(state=State.OK, notice="; ".join(detail_fields))

        for suffix, total_value, metric_name in (
            ("rx", rx_total, "fortigate_ipsec_rx_bandwidth"),
            ("tx", tx_total, "fortigate_ipsec_tx_bandwidth"),
        ):
            try:
                rate = get_rate(value_store, f"{item}.{suffix}", now, total_value, raise_overflow=True)
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
