"""Graphing definitions for FortiGate IPsec metrics."""

from cmk.graphing.v1 import Title, graphs, metrics

UNIT_BYTES_PER_SECOND = metrics.Unit(metrics.IECNotation("B/s"))

metric_fortigate_ipsec_rx_bandwidth = metrics.Metric(
    name="fortigate_ipsec_rx_bandwidth",
    title=Title("FortiGate IPsec RX"),
    unit=UNIT_BYTES_PER_SECOND,
    color=metrics.Color.LIGHT_BLUE,
)

metric_fortigate_ipsec_tx_bandwidth = metrics.Metric(
    name="fortigate_ipsec_tx_bandwidth",
    title=Title("FortiGate IPsec TX"),
    unit=UNIT_BYTES_PER_SECOND,
    color=metrics.Color.DARK_GREEN,
)

graph_fortigate_ipsec_bandwidth = graphs.Graph(
    name="fortigate_ipsec_bandwidth",
    title=Title("FortiGate IPsec Bandwidth"),
    simple_lines=[
        "fortigate_ipsec_rx_bandwidth",
        "fortigate_ipsec_tx_bandwidth",
    ],
)
