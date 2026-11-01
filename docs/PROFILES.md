# Firewall profile design

NIRUSEC profiles are **UFW policy presets**, not service managers. A profile never
starts or stops `sshd`, `tailscaled`, Docker or a user session. Every profile
except Off keeps an explicit recovery path.

| Profile | Incoming policy | Notes |
|---|---|---|
| **Off** | UFW disabled | Explicit warning; all listening services are exposed. Not a default. |
| **Soft** | Tailscale, private-network SSH/web, DHCP/mDNS | Everyday workstation. |
| **Medium** | Tailscale; no private-network/public SSH/web | SSH is authorized by Tailscale ACL. |
| **Hard** | Tailscale, loopback, DHCP | No LAN/public ingress; physical console is break-glass. |
| **Gaming** | Soft plus documented LAN game ports | No public game ports or UPnP. |

Medium and Hard currently have the same effective base policy apart from their
description; treat them as tailnet-only presets until a real difference is
implemented.

## Active profile state

The GUI reads `/run/nirusec/profile.json` without authentication. It contains
only the profile id/label, transaction timestamps, last message and whether UFW
was enabled. It never contains credentials. The GUI displays one of:

- **verified** — the last managed profile was kept and the UFW files have not
  changed since confirmation;
- **pending / expired** — a rollback window is active or overdue;
- **changed** — UFW files have newer timestamps than the confirmation;
- **custom** — no NIRUSEC profile transaction is recorded;
- **off** — the Off profile is confirmed.

External edits made directly through UFW may only be detected through file
timestamps, so NIRUSEC reports them as changed/custom rather than claiming a
definitive match.

## Transaction and rollback

Before changing anything, the helper:

1. acquires a non-blocking root lock in `/run/nirusec/firewall.lock`;
2. copies `/etc/ufw` and `/etc/default/ufw` into a unique root-only backup;
3. records the previous UFW enabled state;
4. writes the pending transaction and arms a 120-second watchdog;
5. applies the profile and enables or disables UFW as the profile requires.

The GUI shows a global countdown and two explicit actions:

- **Keep this profile** writes the confirmation marker and records the kept
  profile.
- **Restore previous** restores the exact backup for this transaction.

If neither happens, the watchdog calls the root helper with the transaction
token. It restores that specific backup and the previous enabled state. A
previously disabled firewall is never silently enabled. If restoration fails,
the GUI is left with a visible rollback-failed state rather than claiming
success.

Manual firewall edits are blocked while a profile transaction is pending. The
user must keep, restore or wait for rollback first.

## Other safety requirements

- Never edit the Tailscale management path as part of an ordinary profile.
- Do not make a profile apply SSH authentication, Tailscale state or package
  updates implicitly.
- Treat Docker published ports as outside UFW; bind them to `127.0.0.1` or the
  Tailscale address when they should not be exposed.
- Mirror IPv4 and IPv6 rules.
- Keep a local-console `--safe-mode` that is simpler than the GUI.
