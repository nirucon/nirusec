# NIRUSEC

**Security, firewall, update and firmware overview for [NIRUX](https://github.com/nirucon/nirux), by Nicklas Rudolfsson.**

NIRUSEC is a quiet Rust/egui desktop tool for inspecting and changing the parts
of a Linux machine that are easy to forget: UFW state, listening services,
blocked traffic, package updates, CPU microcode, firmware and running Docker
containers. It follows the active NIRUX theme and works in narrow tiling
layouts as well as large windows.

**Current release: 0.1.8.** It is a working core, not an independent security
audit. The limitations at the bottom are deliberate and visible in the UI.

## Install

With NIRUX:

```sh
nirux extras select nirusec
nirux extras install nirusec
```

The NIRUX extra downloads the prebuilt release; no Rust build is performed on
the target. The release is one x86_64 glibc binary. The same binary supports
the GUI and the root helper mode used by PolicyKit. The installer copies that
artifact to the fixed root-owned helper path and installs the PolicyKit action.

Standalone release installation:

```sh
tar -xzf nirusec-0.1.8-x86_64-linux-gnu.tar.gz
./install.sh
```

Run the installer as your desktop user, not with `sudo`; it requests sudo only
for the fixed root helper and PolicyKit action. `./install.sh` uses the verified
binary in the archive. Without a binary it downloads the published release and
checks `SHA256SUMS`. Installation installs UFW as a dependency but **does not
enable it** and never flashes firmware.

## Use

```sh
nirusec                         # GUI
nirusec --open firewall         # open a specific view
nirusec --check                 # write the shared status cache
nirusec --status [--json]       # read the cache
sudo /usr/local/libexec/nirusec-helper safe-mode    # emergency recovery
sudo /usr/local/libexec/nirusec-helper restore-ufw  # restore latest backup
```

`--check` is intentionally short-lived. NIRUBAR triggers it when the shared
cache is stale, so a running bar does not start package queries every second.

### Overview

The first screen shows the hostname, firewall state, number of listening
sockets, available package updates, firmware recommendations, Docker state and
the age of the last check. Unknown or failed checks are shown as unknown, not
as a fresh green result.

### Firewall

- Read UFW enabled state and default policies.
- Load the actual numbered rules after an explicit PolicyKit authentication.
- Show the **active profile** on every view: verified, pending, changed, custom
  or intentionally off.
- Apply Off/Soft/Medium/Hard/Gaming presets with a global 120-second countdown,
  **Keep this profile** and **Restore previous** actions.
- The root-owned transaction backs up `/etc/ufw` and `/etc/default/ufw`, records
  whether UFW was enabled, and arms the rollback timer before applying rules.
  Automatic rollback restores that exact backup and never turns on a firewall
  that was previously disabled.
- Enable/disable UFW.
- Add a validated incoming rule: allow/limit/deny/reject, TCP/UDP, port or
  range, optional IP/CIDR source and comment.
- Delete a numbered rule after confirmation.
- **Emergency safe mode** backs up `/etc/ufw`, resets to a small recovery
  policy and makes SSH reachable again. It is intentionally more open than a
  normal profile and is intended for a local console or trusted SSH session.

### Ports and logs

- Show listening TCP/UDP sockets with loopback, LAN, Tailscale or all-interface
  scope.
- Show UFW logs when readable, including blocked/allowed counts and a compact
  bar chart of the most common blocked ports.
- Report unavailable logs or permissions instead of implying there was no
  blocked traffic.

### Updates

- Debian: configured APT upgrade set; no false claim of security-only
  classification when the repository metadata does not provide it.
- Arch: full supported `pacman -Syu`; security advisories are not a partial
  upgrade mechanism.
- Void: supported XBPS transaction.
- Package updates run through the fixed privileged helper and show the package
  manager result. A lock or failure is reported, not hidden.

### Firmware and microcode

- Recommend hardware-relevant distribution packages, including the matching
  Intel/AMD microcode package where detectable.
- Show whether `fwupd` is available and summarise its update state.
- Install the recommended firmware packages only after confirmation.
- Device flashing is a separate, explicit action with the usual power/reboot
  requirements. A status check never flashes anything.
- Touchpad tap/scroll settings are libinput/Xorg settings, not firmware; those
  remain in NIRUX input configuration.

### Docker

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

- The GUI runs as the normal user; only the small helper is privileged.
- The helper accepts validated operations and explicit arguments, never a shell
  string or arbitrary executable.
- UFW files are backed up before safe mode; the GUI does not silently replace
  another firewall manager.
- Docker published ports bypass UFW. Bind them to `127.0.0.1` or the Tailscale
  address if they should not be exposed.
- For recovery guidance, see [Emergency access](docs/EMERGENCY.md).

## Current limitations

- Firewall profiles are implemented with a 120-second rollback window; see
  [Profile design](docs/PROFILES.md). The active-profile display is based on
  the last NIRUSEC transaction plus UFW file timestamps; a configuration edited
  outside NIRUSEC is reported as changed/custom rather than guessed.
- Fail2ban guidance exists, but NIRUSEC does not install or automatically
  reconfigure fail2ban yet; see [Fail2ban guidance](docs/FAIL2BAN.md).
- UFW application profiles, arbitrary destination/interface editing and saved
  profile snapshots are not complete.
- Rich long-term log aggregation and every PolicyKit/update/firmware failure
  path still need broader live coverage.
- Docker and `fwupd` behaviour depends on the installed daemon and permissions.
- The live acceptance record is in [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --locked
./install.sh --build        # local development install (never on targets)
```

Run the privileged helper directly only in a disposable environment:
`NIRUSEC_HELPER=/path/to/nirusec` lets the GUI use that helper instead of
`pkexec`.

- [End-to-end implementation brief](AGENTS.md)

MIT. Copyright 2026 Nicklas Rudolfsson.
