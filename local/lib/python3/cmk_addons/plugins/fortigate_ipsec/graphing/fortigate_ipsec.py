"""Graphing definitions for FortiGate IPsec metrics."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph
from cmk.graphing.v1.metrics import Color, IECNotation, Metric, Unit
from cmk.graphing.v1.perfometers import Bidirectional, FocusRange, Open, Perfometer

UNIT_BYTES_PER_SECOND = Unit(IECNotation("B/s"))

metric_fortigate_ipsec_rx_bandwidth = Metric(
    name="fortigate_ipsec_rx_bandwidth",
    title=Title("FortiGate IPsec RX"),
    unit=UNIT_BYTES_PER_SECOND,
    color=Color.LIGHT_BLUE,
)

metric_fortigate_ipsec_tx_bandwidth = Metric(
    name="fortigate_ipsec_tx_bandwidth",
    title=Title("FortiGate IPsec TX"),
    unit=UNIT_BYTES_PER_SECOND,
    color=Color.DARK_GREEN,
)

graph_fortigate_ipsec_bandwidth = Graph(
    name="fortigate_ipsec_bandwidth",
    title=Title("FortiGate IPsec Bandwidth"),
    simple_lines=[
        "fortigate_ipsec_rx_bandwidth",
        "fortigate_ipsec_tx_bandwidth",
    ],
)

# Represent RX (left) and TX (right) in a single Perf-O-Meter for quick direction insight
perfometer_fortigate_ipsec_bandwidth = Bidirectional(
    name="perfometer_fortigate_ipsec_bandwidth",
    left=Perfometer(
        name="perfometer_fortigate_ipsec_rx",
        focus_range=FocusRange(Open(0), Open(100 * 1024 * 1024)),
        segments=["fortigate_ipsec_rx_bandwidth"],
    ),
    right=Perfometer(
        name="perfometer_fortigate_ipsec_tx",
        focus_range=FocusRange(Open(0), Open(100 * 1024 * 1024)),
        segments=["fortigate_ipsec_tx_bandwidth"],
    ),
)
