"""Server-side call configuration for the FortiGate IPsec special agent."""

from __future__ import annotations

from cmk.server_side_calls.v1 import (
    SpecialAgentCommand,
    SpecialAgentConfig,
    noop_parser,
)
from cmk.utils.exceptions import MKGeneralException

AGENT_NAME = "fortigate_ipsec"


def _fortigate_ipsec_commands(params, host_config):
    api_key = params.get("api_key")
    if api_key is None:
        raise MKGeneralException("FortiGate IPsec special agent requires an API token")
    if hasattr(api_key, "unsafe"):
        api_key_value = api_key.unsafe()
    else:
        api_key_value = str(api_key)

    hostname = getattr(host_config.primary_ip_config, "address", None)
    if not hostname:
        raise MKGeneralException(
            "FortiGate IPsec special agent could not determine a host address."
        )

    args = ["--hostname", hostname, "--api-key", api_key_value]

    port = params.get("port")
    if port and port != 443:
        args += ["--port", str(port)]

    if params.get("no_cert_check"):
        args.append("--no-cert-check")

    yield SpecialAgentCommand(
        command_arguments=args,
    )


special_agent_fortigate_ipsec = SpecialAgentConfig(
    name=AGENT_NAME,
    parameter_parser=noop_parser,
    commands_function=_fortigate_ipsec_commands,
)