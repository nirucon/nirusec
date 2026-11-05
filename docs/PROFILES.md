# Firewall profile design

NIRUSEC profiles are **UFW policy presets**, not service managers. A profile never
starts or stops `sshd`, `tailscaled`, Docker or a user session. Every profile
except Off keeps your Tailscale devices able to reach the machine.

All profiles except Off: default **deny incoming**, **allow outgoing**.

| Profile | Purpose | Incoming allowed |
|---|---|---|
| **Soft** | Home or office network | loopback; everything on `tailscale0`; Tailscale direct UDP 41641; DHCP client 68/udp; SSH 22, HTTP 80, HTTPS 443 and mDNS 5353/udp from the local network |
| **Medium** | Public Wi-Fi and travel | loopback; everything on `tailscale0`; Tailscale direct UDP 41641; DHCP 68/udp. Nothing from the local network. |
| **Hard** | Lockdown — Tailscale only | loopback; everything on `tailscale0`. Tailscale direct UDP is closed too (Tailscale may fall back to slower relays). |
| **Gaming** | Home network with LAN games | Soft, plus Steam (27015–27050, 27036 tcp; 3478, 4380, 27015–27050, 27031–27036 udp) and Minecraft (25565/tcp) from the local network only. No public ports, no UPnP. |
| **Off** | No protection | UFW disabled. Shown as *Firewall is off*, never as protected. |

“Local network” means `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12` and,
when UFW's IPv6 support is on, `fd00::/8` (unique local) and `fe80::/10`
(link-local). 0.1.x profiles only allowed the IPv4 ranges.

`nirusec --profile-rules NAME` prints the exact UFW rules of a profile
(including this machine's local exceptions when run as root).

## Local exceptions

A machine sometimes needs one more opening (a printer port, a lab subnet, a
`wg0` interface). Tick *Keep it on every profile* when adding a rule, and
NIRUSEC stores it in `/etc/nirusec/local-exceptions.toml` (root, 0600):

- rules are validated exactly like rules entered in the GUI (action, protocol,
  port/range, source address/CIDR, interface name, comment);
- block rules are placed before the profile, allow rules after it;
- every profile preview lists the exceptions it keeps; Off uses none;
- *Stop keeping…* removes an exception (the live rule stays until the next
  profile switch or until you remove it);
- the file never leaves the machine: not in Git, releases, diagnostics or the
  user's status cache.

## Active profile state and verification

The public state is `/var/lib/nirusec/state.json` (0644, no secrets). It
survives reboots. States shown in the GUI:

- **Profile: Soft — Home or office network · verified** — kept, and a root
  check found the live UFW files identical to the snapshot NIRUSEC took when it
  last changed them;
- **changed outside NIRUSEC** — the root check found a difference (the files
  are listed); the unprivileged status only says *may have changed* based on
  timestamps and never claims *verified*;
- **Custom rules (based on Soft)** — rules were edited in NIRUSEC after a
  profile;
- **Trying …** — a rollback window is open;
- **interrupted** — the machine restarted during a rollback window (detected
  through the boot id): the change is still active and must be kept or
  restored before anything else changes;
- **Firewall is off** — the Off profile, or the firewall was turned off.

The status check also reports whether UFW is really running and whether its
boot service (systemd unit or runit service) is enabled; turning the firewall
on through NIRUSEC enables the boot service.

## Transaction and rollback

Every firewall change runs as one transaction:

1. one lock for all NIRUSEC write paths (`/run/nirusec/firewall.lock`);
2. a root-only copy of `/etc/ufw` and `/etc/default/ufw` plus the running
   state in `/var/backups/nirusec/ufw-*` (20 kept);
3. for changes that can cut access, a pending record in
   `/var/lib/nirusec/tx/` (0600) and a watchdog: a transient systemd timer
   `nirusec-rollback-<token>.timer` in the system manager on Debian/Arch, or a
   detached root process on runit (Void). Both survive GUI exit and logout;
4. the change;
5. on success a snapshot for verification, an entry in the change history,
   and — for windowed changes — the confirmation token goes back to the GUI
   that started the change only.

Windowed (Keep / Undo, 120 s by default): profile switches (including Off),
turning UFW on, block rules, removing allow rules, more restrictive default
policies and restoring older settings. Allow rules and turning the firewall
off cannot cut access; they are applied directly, backed up and undoable from
the history.

If neither Keep nor Undo happens, the watchdog restores that exact backup and
the previous running state. A firewall that was off is never silently switched
on. If the restore fails, the state becomes *rollback failed* and the GUI says
so instead of claiming success. While a change is unresolved, other changes
are refused — except emergency safe mode, which cancels it.

A root-owned `/etc/nirusec/settings.toml` (not writable by others) may set
`rollback_seconds = 20…600`.

### How a profile is applied

0.1.x ran `ufw --force reset` and ~25 single commands. `reset` switched the
firewall off for the whole apply (seconds) and replaced customised
`before.rules`/`after.rules` with package defaults.

0.2 builds the profile in a staging copy of `/etc/ufw`: every UFW command runs
in a private mount and network namespace where `/etc/ufw` and
`/etc/default/ufw` are bind mounts of the staging copy, so nothing touches the
live firewall. Then only `user.rules`, `user6.rules`, `/etc/default/ufw` and the
log prefixes in `after*.rules` are installed atomically, and the user chains
are replaced with `iptables-restore -n` / `ip6tables-restore -n` (one table
commit each, no moment without filtering). When the default policy itself
changes, or UFW was off, UFW's own reload/enable is used.

## Other safety requirements

- Never edit the Tailscale management path as part of an ordinary profile.
- Do not make a profile apply SSH authentication, Tailscale state or package
  updates implicitly.
- Treat Docker published ports as outside UFW; bind them to `127.0.0.1` or the
  Tailscale address when they should not be exposed.
- Mirror IPv4 and IPv6 rules.
- Keep a local-console safe mode that is simpler than the GUI.
