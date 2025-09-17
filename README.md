# FortiGate IPsec Checkmk Extension

This repository contains a Checkmk extension package (`fortigate_ipsec`) that monitors the state of IPsec VPN tunnels on FortiGate firewalls via the FortiOS REST API. The special agent queries `/api/v2/monitor/vpn/ipsec`, normalises the tunnel metadata (remote gateway, type, port, connection counts) and preserves every phase2 proxy selector so the agent-based check can report per-proxy status together with cumulative RX/TX counters. It also exposes per-tunnel receive/transmit bandwidth metrics (`fortigate_ipsec_rx_bandwidth`, `fortigate_ipsec_tx_bandwidth`) so Checkmk can graph historical throughput. The special agent backs off automatically when FortiOS returns HTTP 429 rate-limit responses.

The codebase is tested against Checkmk 2.2 and 2.3 releases. The special agent call automatically adapts to the evolving `SpecialAgentCommand` API so the same MKP works across both generations. When running on older builds that lack `MKGeneralException`, a local fallback keeps configuration errors readable. You can optionally scope API calls to a specific VDOM, narrow the JSON payload with FortiOS filter expressions, or request a single tunnel through the dedicated `tunnel` query parameter exposed in the Setup rule.

## Repository Layout

```
local/
|-- lib/python3/
|   |-- cmk_addons/plugins/fortigate_ipsec/
|   |   |-- agent_based/fortigate_ipsec.py      # Check plug-in
|   |   |-- checkman/fortigate_ipsec            # Check manual
|   |   |-- graphing/fortigate_ipsec.py         # Graphing stub
|   |   |-- libexec/agent_fortigate_ipsec       # Special agent script
|   |   |-- rulesets/fortigate_ipsec.py         # Ruleset definition (Setup)
|   |   |-- rulesets/fortigate_ipsec_bakery.py  # Agent bakery ruleset stub
|   |   `-- server_side_calls/fortigate_ipsec.py  # Special agent call configuration
|   |-- cmk/base/cee/plugins/bakery/
|   |   `-- fortigate_ipsec.py                  # Bakery plug-in stub
|   `-- cmk/gui/plugins/wato/
|       `-- fortigate_ipsec.py                  # Loader for the WATO ruleset
```

Configuration for [oposs/mkp-builder](https://github.com/oposs/mkp-builder) resides in `.mkp-builder.ini`. The GitHub Actions workflow in `.github/workflows/build.yml` can produce signed release assets automatically.

## Building the MKP

### Locally with mkp-builder

1. Install `mkp-builder` from the referenced repository.
2. Run the build command from the project root:
   ```bash
   mkp-builder build
   ```
   The packaged MKP is placed in `build/` alongside a generated manifest.

### Via GitHub Actions

Tag the repository with the desired package version (`v2.3.0p34` style) and push it, or trigger the `Build MKP Package` workflow manually by providing the `version` input. The workflow checks out the repository, runs `oposs/mkp-builder@v2`, and uploads the resulting MKP to the GitHub release associated with the tag.

## Deploying on Checkmk

1. Download the generated `fortigate_ipsec-<version>.mkp`.
2. Upload the package in Checkmk (`Setup -> Extension Packages -> Upload & Install`).
3. Create a rule via Setup -> Agents -> Other Integrations -> Fortinet FortiGate IPsec and provide the API token. Adjust HTTPS port, disable TLS verification, scope to a VDOM, set the optional tunnel name, or add FortiOS filter expressions as needed.
4. Assign the rule to the FortiGate host, then perform a service discovery to create per-tunnel services reporting status and RX/TX counters.

## License

This project is licensed under the GPL-3.0. See [LICENSE](LICENSE) for details.

