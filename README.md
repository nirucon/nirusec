# NIRUSEC

**A planned Rust security and maintenance GUI for [NIRUX](https://github.com/nirucon/nirux), by Nicklas Rudolfsson.**

Firewall rules, network exposure, system updates and firmware, presented in a
quiet, responsive interface that follows the active NIRUX theme.

## Project status

**Specification repository — the application is not implemented yet.**
This repository contains the product brief and implementation instructions.
There is no installable release, working installer or completed security audit.
The next implementation agent should read [AGENTS.md](AGENTS.md) and build the
product through live validation, packaging and deployment on the machines the
owner explicitly names for that implementation session.

## What NIRUSEC should do

### Overview

A useful first screen answers:

- Is the firewall active, and what are its incoming/outgoing defaults?
- Which services listen on localhost, LAN, Tailscale or all interfaces?
- Are SSH and Tailscale running? What access is currently exposed?
- Are system/security updates available, or is a restart required?
- Is relevant device firmware or CPU microcode missing or outdated?
- When was each result checked, and did that check actually succeed?

Display concrete facts rather than a made-up security score. An unavailable,
stale or failed check must never appear as a fresh green result.

### Firewall

UFW is the first supported management backend:

- Enable/disable UFW; inspect and change default policies and logging level.
- Add, inspect, edit and delete rules for TCP/UDP, ports/ranges, source and
  destination networks, IPv4/IPv6, direction and interfaces.
- Support UFW application profiles, ordered rules and rate limiting where the
  installed UFW supports them. Explain unsupported features honestly.
- Show both a readable description and the actual structured rule parameters.
- Provide search, filtering, configuration export, saved profiles and recovery.
- Detect firewalld/direct nftables or other active managers before changing UFW;
  do not silently replace an existing firewall configuration.
- Detect active SSH/Tailscale access and provide timed, privileged automatic
  rollback for connectivity-affecting changes. Rollback must survive a GUI
  crash, disconnect or logout.

Example: **Allow SSH from Tailscale on `tailscale0`, TCP port 22.**

### Ports and logs

- Show listening TCP/UDP sockets, bound addresses, interfaces and owning
  processes when permissions allow. Distinguish listening from established
  connections and firewall policy from actual reachability.
- Filter existing firewall logs by time, source, destination, port and action.
- Use small graphs for blocked traffic over time and the most frequently
  blocked ports/sources. No synthetic data or continuous packet capture.
- Show an explicit empty/unavailable state when logging is off or records cannot
  be read. Missing logs do not mean there were no blocked packets.
- Keep retention and disk use bounded; redact sensitive details from exported
  diagnostics and never collect packet payloads by default.

### System and security updates

Use distribution package managers and their normal signature verification:

| Distribution | Update behaviour |
|---|---|
| Debian | Identify updates from configured security origins where reliable; preview package/dependency changes and install through APT. Also offer a normal system update. |
| Arch Linux | Offer a full supported `pacman -Syu` transaction. Flag relevant advisories when available; never manufacture a security-only partial upgrade. |
| Void Linux | Use supported XBPS update sequencing and full transactions. Show advisory information when available without promising complete security-only classification. |

Show available changes, progress, package-manager locks, failures and any
restart/logout requirements. Reuse existing NIRUX/NIRUFLOW update integration
where appropriate instead of creating competing package-manager wrappers.

### Firmware and microcode

Firmware installation and updates belong in NIRUSEC, with three distinct views:

1. **OS firmware packages:** GPU, Wi-Fi, Bluetooth, audio/SOF and other relevant
   runtime firmware provided by the distribution.
2. **CPU microcode:** appropriate Intel/AMD packages and activation/reboot state.
3. **Device firmware updates:** BIOS/UEFI and supported devices through `fwupd`
   and configured vendor/LVFS sources when available.

Recommend hardware-relevant packages; do not install every firmware package.
Explain that touchpad tap-to-click and two-finger scrolling are usually
libinput/Xorg settings, not missing firmware. Link to the existing NIRUX input
controls rather than duplicating those settings.

Detect firmware repository availability and hardware support on each distro.
Do not silently rewrite Debian repository components, add third-party feeds,
download unsigned blobs or claim `fwupd` supports an unsupported device. Show
the installed version, available version, source, update conditions and results.
Device flashing must be an explicit user action with the tool's power/reboot
requirements visible; checking for updates must not flash anything.

### Profiles and later extensions

Saved Home/Public/Server firewall profiles and a bounded local change history
are part of the intended product. After the core is verified, useful extensions
include read-only SSH hardening status, Fail2ban status and richer local
Tailscale exposure information. Tailnet ACL editing and central remote fleet
management are separate integrations, not assumed capabilities of the local GUI.

## Interface and themes

Use Rust with egui/eframe unless repository research reveals a concrete reason
to choose otherwise. The design must work in narrow laptop tiling windows:

- Wide windows: navigation, rule list and details side by side.
- Narrow windows: compact navigation, one view at a time and a clear Back action.
- Tables become readable cards/rows; forms stack; essential controls never
  require horizontal scrolling or mouse hover.
- Suggested views: **Overview · Firewall · Ports · Logs · Updates · Firmware**.
- Keyboard navigation, visible focus, search/filter, usable scaling and
  accessible status text accompany icons and colours.
- Follow active NIRUX built-in/custom themes and appearance overrides, with
  live reload, correct precedence, light/dark contrast and reduced motion.
- Use small functional graphs, not decorative animations or a busy dashboard.

Verify widths of **420, 640, 960 and 1440 logical pixels**, laptop half/third
tiling, small heights, high DPI, long labels and all built-in themes. See
[the acceptance checklist](docs/ACCEPTANCE.md).

## NIRUX integration

- Ship as a **selected optional extra**, not a mandatory always-running desktop
  service. Provide a standalone installer and desktop entry too.
- NIRULAUNCHER opens NIRUSEC and relevant native views through documented CLI
  entry points.
- NIRUBAR gets **one icon, no permanent text**. Hide it when NIRUSEC is absent;
  click opens the GUI; tooltip describes cached state and its age.
- Use the theme's normal/warning/error roles. Critical policy violations use
  the error role, normally red, together with meaningful text.
- Send critical state transitions through **NIRUNOTIFY** using critical urgency.
  Deduplicate them, respect notification/lock privacy and user policy, and do
  not send another alert on every poll. Ordinary updates are not automatically
  critical incidents.
- Document release pins, checksums, capabilities and compatibility with the
  existing NIRUX suite. Keep unrelated apps and desktop settings intact.

## Resource model

The closed GUI should cost effectively nothing between scheduled checks.

- Event-driven rendering; no continuous repaint loop or animated idle graphs.
- Expensive checks belong in a short-lived, bounded scheduled checker.
- systemd timers on Arch/Debian; an explicitly verified supported scheduling
  mechanism on Void/runit, with clean install/remove behaviour.
- One versioned, atomically written status cache feeds every NIRUBAR instance.
  Each monitor must not run its own package-manager checks or parse whole logs.
- Refresh graphs only while visible; use bounded streaming/incremental reads,
  log rotation, command timeouts and cancellation.
- Reap every child process, cap concurrency, avoid overlapping checks and test
  memory/FD/thread/process behaviour over repeated operations.
- Measure release builds including checker/helper/Xorg/compositor overhead.
  Report observed numbers, not claims of zero CPU or guaranteed absence of bugs.

## Permissions and installation

The GUI runs as the normal user. A small root-owned helper exposes a fixed set
of validated operations through narrowly scoped Polkit authorization. It must
not offer arbitrary shell execution, arbitrary file writes, or saved passwords.

Installation must provision required runtime dependencies using the correct
package names for **Arch Linux, Debian and Void**, verify the installation,
preserve existing firewall configuration, and support update/uninstall without
deleting user data unexpectedly. Optional capabilities install their own
dependencies on request and remain honest when unavailable.

Installing NIRUSEC must not activate UFW, change remote access, enable telemetry
or flash firmware automatically.

## Implementation and live testing

[AGENTS.md](AGENTS.md) is the end-to-end implementation assignment, including
architecture, authorization, dependency handling, distro-specific requirements,
bare-metal verification, release/update responsibilities and completion gates.

The owner will name deployment targets when pointing the agent at this repo.
Those machines may be used to build, benchmark and test actual release binaries.
No machine credentials belong in this repository, documentation or screenshots.

## License

MIT. Copyright 2026 Nicklas Rudolfsson.
