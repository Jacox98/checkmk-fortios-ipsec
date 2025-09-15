"""Ruleset definition for configuring the FortiGate IPsec special agent."""

from __future__ import annotations

from cmk.rulesets.v1.form_specs import (
    Checkbox,
    DictElement,
    Dictionary,
    Integer,
    Password,
    String,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import Help, SpecialAgent, Title, Topic


def _formspec_fortigate_ipsec() -> Dictionary:
    return Dictionary(
        title=Title("Fortinet FortiGate IPsec"),
        help_text=Help(
            "Configure access to a FortiGate firewall via the FortiOS REST API to collect "
            "IPsec tunnel status and traffic metrics."
        ),
        elements={
            "api_key": DictElement(
                required=True,
                parameter_form=Password(
                    title=Title("API token"),
                    migrate=migrate_to_password,
                    help_text=Help(
                        "API token generated on the FortiGate with read access to IPsec monitoring data."
                    ),
                ),
            ),
            "hostname": DictElement(
                required=False,
                parameter_form=String(
                    title=Title("FortiGate hostname or IP"),
                    help_text=Help(
                        "Leave empty to use the host's primary IP address configured in Checkmk."
                    ),
                ),
            ),
            "port": DictElement(
                required=False,
                parameter_form=Integer(
                    title=Title("HTTPS port"),
                    default_value=443,
                    minvalue=1,
                    maxvalue=65535,
                ),
            ),
            "no_cert_check": DictElement(
                required=False,
                parameter_form=Checkbox(
                    title=Title("Disable TLS certificate verification"),
                    label="Skip TLS certificate verification",
                ),
            ),
        },
    )


rule_spec_fortigate_ipsec = SpecialAgent(
    topic=Topic.NETWORKING,
    name="fortigate_ipsec",
    title=Title("Fortinet FortiGate IPsec"),
    parameter_form=_formspec_fortigate_ipsec,
)