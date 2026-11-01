# Firewall profile design

NIRUSEC profiles are planned as **UFW policy presets**, not service managers.
A profile must never start/stop `sshd`, `tailscaled`, Docker or a user session.
Every profile except Off keeps an explicit recovery path.

| Profile | Incoming policy | Notes |
|---|---|---|
| **Off** | UFW disabled | Explicit warning; all listening services are exposed. Not a default. |
| **Soft** | Tailscale, LAN SSH, DHCP/mDNS; optional LAN web | Everyday workstation. Recommended current starting point. |
| **Medium** | Tailscale; no LAN/public SSH | SSH is authorized by Tailscale ACL; ordinary outgoing browsing remains. |
| **Hard** | Tailscale only, loopback, core system traffic | No LAN/public ingress; Docker published ports must be loopback/Tailscale-bound. Physical console is the break-glass path. |
| **Gaming** | Soft plus documented LAN game ports for a limited period | No public game ports or UPnP by default; temporary hosting is explicit. |

## Safety requirements for implementation

- Preview the effective rule diff and back up UFW before applying.
- Arm a root-owned **auto-revert timer** before changing a profile. The timer
  survives GUI crash/logout and restores the last known-good profile unless the
  user confirms a new SSH connection.
- Never edit the Tailscale management path as part of an ordinary change.
- Do not make a profile apply SSH authentication, Tailscale state or package
  updates implicitly. Those are separate, explicit operations.
- Treat Docker published ports as outside UFW; show the warning and recommend
  `127.0.0.1`/Tailscale bindings.
- Mirror IPv4 and IPv6 rules.
- Keep profile history and a one-click **Restore last working profile**.
- Provide a local-console `--safe-mode` that is simpler than the GUI.

Profiles are not yet fully implemented in the GUI. The recovery CLI and safe
mode exist in this release; the profile presets are the next hardening step.
