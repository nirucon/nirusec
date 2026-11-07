# NIRUSEC guide

The views, the safety model and the known limitations in detail. Back to the
[README](../README.md).

## Overview

The first screen shows the hostname, firewall state, number of listening
sockets, available package updates, firmware recommendations, Docker state and
the age of the last check. Unknown or failed checks are shown as unknown, not
as a fresh green result. The cards open the matching view.

## Firewall

The Firewall view is written for people who do not read UFW output.

- **Plain status** at the top: *Protected — incoming connections are blocked,
  except: ✔ everything from your Tailscale devices ✔ SSH (22/tcp) from the local
  network …*, or *Not protected* / *Firewall is off* with the reason. It also
  shows the active profile, whether the live rules still match what NIRUSEC
  last set (**verified** / **changed outside NIRUSEC**), whether UFW starts at
  boot, the SSH listener, current SSH sessions by origin (Tailscale, local
  network, internet) and whether Tailscale is up. Reading this needs no
  password in the active desktop session.
- **Profiles** — Soft (home/office), Medium (public Wi-Fi and travel), Hard
  (Tailscale only), Gaming (home + LAN games) and Off. *Preview* shows what the
  profile allows, how many rules are added/removed/kept, the exact UFW commands,
  the local exceptions it keeps and a warning when it would cut SSH you are
  using right now. See [Profile design](PROFILES.md).
- **Allow or block something** — pick an app or port (SSH, web server,
  LocalSend, KDE Connect, Syncthing, Minecraft or a port/range) and where from
  (your Tailscale devices, the local network, anywhere, or one address). The
  preview shows the plain-language result and the exact UFW commands before
  anything changes. *Keep it on every profile* stores the rule as a root-owned
  local exception for this machine only.
- **Current rules** in plain language, one row per rule with its IPv4 and IPv6
  halves merged; removing a rule removes both halves after checking that
  neither changed since it was shown.
- **Recent changes** with *Restore before this…* for every backed-up change,
  and **Emergency safe mode**.

**Safe undo.** Anything that can cut access — switching profile, turning the
firewall on, block rules, removing allow rules, restoring older settings —
is backed up and *tried* for 120 seconds. A banner on every view says
*Keep the new firewall settings? Undo in 97 s* with **Keep** and **Undo now**.
Without Keep, the previous settings return automatically, even if NIRUSEC is
closed, crashes or you log out (a systemd timer on Debian/Arch, a detached root
watchdog on Void/runit). After a restart during that window the change is
shown as *interrupted* and NIRUSEC asks whether to keep or restore it.

Profiles are built off-line in a private namespace and swapped in with one
table update, so the firewall is never switched off while a profile is
applied, and customised `before.rules`/`after.rules` are left alone.

## Ports and logs

- Show listening TCP/UDP sockets with loopback, LAN, Tailscale or all-interface
  scope.
- Show UFW logs when readable, including blocked/allowed counts and a compact
  bar chart of the most common blocked ports.
- Report unavailable logs or permissions instead of implying there was no
  blocked traffic.

## Updates

- Debian: configured APT upgrade set; no false claim of security-only
  classification when the repository metadata does not provide it.
- Arch: full supported `pacman -Syu`; security advisories are not a partial
  upgrade mechanism.
- Void: supported XBPS transaction.
- Package updates run through the fixed privileged helper and show the package
  manager result. A lock or failure is reported, not hidden.

## Firmware and microcode

- Recommend hardware-relevant distribution packages, including the matching
  Intel/AMD microcode package where detectable.
- Show whether `fwupd` is available and summarise its update state.
- Install the recommended firmware packages only after confirmation.
- Device flashing is a separate, explicit action with the usual power/reboot
  requirements. A status check never flashes anything.
- Touchpad tap/scroll settings are libinput/Xorg settings, not firmware; those
  remain in NIRUX input configuration.

## Docker

Docker is detected through the unprivileged `docker ps` interface. Running
containers, images, status and published ports are shown. If the user cannot
access Docker, NIRUSEC says so rather than requesting root unnecessarily.

## NIRUX integration

- Responsive layout: sidebar + detail on wide screens, compact navigation and
  one view at a time on narrow tiling layouts.
- Active NIRUX built-in/custom theme and appearance colours, with live theme
  changes.
- NIRUBAR entry with a shield icon only, placed before Quick Settings. It reads
  one shared cache and triggers at most one short-lived checker at a time.
- NIRULAUNCHER/desktop entry through the normal application entry.
- Critical state transitions go through NIRUNOTIFY with critical urgency. The
  first unknown-to-critical transition is not treated as a noisy repeat, and
  ordinary available updates are not classified as critical incidents.

## Safety

- The GUI runs as the normal user; only the small helper is privileged. Every
  helper operation has its own PolicyKit action. Changes ask for the
  administrator password **every time**; only reading the firewall status and
  keeping/undoing a change that the same window just made (random token) are
  allowed without a password, and only in the active local session. See the
  [0.2 review](REVIEW-0.2.md) for the threat model.
- The helper accepts validated operations with an exact argument count and
  explicit arguments, never a shell string or arbitrary executable; children
  run with a clean environment.
- All firewall writes share one lock and a root-only backup in
  `/var/backups/nirusec` (20 kept). NIRUSEC state lives in `/var/lib/nirusec`
  (public state 0644 without secrets; history and transactions 0600).
- Local exceptions live in `/etc/nirusec/local-exceptions.toml` (root, 0600),
  are never part of Git, releases or the user cache, and are shown in every
  profile preview.
- Docker published ports bypass UFW. Bind them to `127.0.0.1` or the Tailscale
  address if they should not be exposed.
- For recovery guidance, see [Emergency access](EMERGENCY.md).

## Current limitations

- Fail2ban guidance exists, but NIRUSEC does not install or automatically
  reconfigure fail2ban yet; see [Fail2ban guidance](FAIL2BAN.md).
- UFW application profiles are shown but not edited; routed/outgoing rules are
  shown but the editor only creates incoming rules.
- Reachability estimates (“SSH likely reachable from …”) evaluate the UFW
  rules in order; they do not see router port forwards, Docker rules or
  Tailscale ACLs.
- Rich long-term log aggregation and every update/firmware failure path still
  need broader live coverage. Void's XBPS self-update sequence is not automated.
- Docker and `fwupd` behaviour depends on the installed daemon and permissions.
- The live acceptance record is in [ACCEPTANCE.md](ACCEPTANCE.md).
