"""Server-side call configuration for the FortiGate IPsec special agent."""

from __future__ import annotations

from inspect import signature
from pathlib import Path
from typing import Any, Dict, Iterable

from cmk.server_side_calls.v1 import (
    SpecialAgentCommand,
    SpecialAgentConfig,
    noop_parser,
)
try:
    from cmk.utils.exceptions import MKGeneralException
except ImportError:
    try:
        from cmk.exceptions import MKGeneralException
    except ImportError:
        class MKGeneralException(Exception):
            """Fallback when Checkmk does not ship MKGeneralException."""

            pass


AGENT_NAME = "fortigate_ipsec"
AGENT_BINARY = Path(__file__).resolve().parent.parent / "libexec" / "agent_fortigate_ipsec"
_SPECIAL_AGENT_COMMAND_PARAMS = signature(SpecialAgentCommand).parameters
# Support both <=2.2 (requires command_path) and >=2.3 (resolves binary automatically).


def _fortigate_ipsec_commands(params: Dict[str, Any], host_config) -> Iterable[SpecialAgentCommand]:
    api_key = params.get("api_key")
    if api_key is None:
        raise MKGeneralException("FortiGate IPsec special agent requires an API token")
    api_key_value = api_key.unsafe() if hasattr(api_key, "unsafe") else str(api_key)

    hostname = getattr(host_config.primary_ip_config, "address", None)
    if not hostname:
        raise MKGeneralException(
            "FortiGate IPsec special agent could not determine a host address."
        )

    arguments = ["--hostname", hostname, "--api-key", api_key_value]

    port = params.get("port")
    if port:
        arguments += ["--port", str(port)]

    if params.get("no_cert_check"):
        arguments.append("--no-cert-check")

    command_kwargs = {"command_arguments": arguments}
    if "command_path" in _SPECIAL_AGENT_COMMAND_PARAMS:  # <=2.2 still expects the explicit binary path
        command_kwargs["command_path"] = str(AGENT_BINARY)
    yield SpecialAgentCommand(**command_kwargs)


special_agent_fortigate_ipsec = SpecialAgentConfig(
    name=AGENT_NAME,
    parameter_parser=noop_parser,
    commands_function=_fortigate_ipsec_commands,
)
