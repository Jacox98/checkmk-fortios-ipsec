# FortiGate IPsec Checkmk Extension

This repository contains a Checkmk extension package (`fortigate_ipsec`) that monitors the state of IPsec VPN tunnels on FortiGate firewalls via the FortiOS REST API. It ships a special agent to collect tunnel data and an agent-based check plug-in that creates one service per tunnel and reports its connectivity alongside traffic counters.

The codebase is tested against Checkmk 2.2 and 2.3 releases. The special agent call automatically adapts to the evolving `SpecialAgentCommand` API so the same MKP works across both generations. When running on older builds that lack `MKGeneralException`, a local fallback keeps configuration errors readable.

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
3. Create a rule via Setup -> Agents -> Other Integrations -> Fortinet FortiGate IPsec and provide the API token (optionally adjust HTTPS port or disable TLS verification).
4. Assign the rule to the FortiGate host, then perform a service discovery to create per-tunnel services reporting status and RX/TX counters.

## License

This project is licensed under the GPL-3.0. See [LICENSE](LICENSE) for details.

