# NIRUSEC

Firewall, ports, updates, firmware and Docker overview for a NIRUX desktop, in plain language.

**Status: alpha** · Part of the [NIRUX](https://github.com/nirucon/nirux) suite · [MIT License](LICENSE)

## About

NIRUSEC is a quiet Rust/egui desktop tool for the parts of a Linux machine that
are easy to forget: the UFW firewall, listening services, blocked traffic,
package updates, CPU microcode, firmware and running Docker containers. It is a
friendly front end for UFW, written for people who do not read `ufw status`
output, and it follows the active NIRUX theme in narrow tiling layouts as well
as large windows.

It is a working core, not an independent security audit. Its limitations are
deliberate and shown in the UI.

## Features

- **Overview:** firewall state, listening sockets, available updates, firmware
  recommendations, Docker and the age of the last check. Unknown or failed checks
  show as unknown, never as a fresh green result.
- **Firewall in plain language:** "Protected, incoming connections are blocked,
  except …", the active profile, whether the live rules still match what NIRUSEC
  last set, SSH listener and sessions by origin, Tailscale state.
- **Profiles:** Soft (home/office), Medium (public Wi-Fi and travel), Hard
  (Tailscale only), Gaming (home and LAN games) and Off, each with a preview of
  the exact UFW commands and a warning when it would cut SSH you are using now.
- **Allow or block something:** an app or port (SSH, web server, LocalSend, KDE
  Connect, Syncthing, Minecraft or a port/range) from your Tailscale devices, the
  local network, anywhere or one address, with an optional per-machine local
  exception that every profile keeps.
- **Safe undo:** anything that can cut access is backed up and tried for 120
  seconds. Without **Keep**, the previous settings return automatically, even if
  NIRUSEC is closed, crashes or you log out.
- **Ports and logs:** listening TCP/UDP sockets by scope (loopback, LAN,
  Tailscale, all interfaces) and UFW logs with the most blocked ports.
- **Updates:** the distribution's normal upgrade (APT, `pacman -Syu`, XBPS)
  through the privileged helper, with the real package-manager result.
- **Firmware and microcode:** matching Intel/AMD microcode and firmware packages,
  `fwupd` status; installing needs confirmation and a status check never flashes.
- **Docker:** running containers, images and published ports through the
  unprivileged `docker ps` interface.
- **NIRUX integration:** a shield icon in NIRUBAR fed by one shared cache,
  critical state changes through NIRUNOTIFY, live NIRUX theme colours.
- **Separated privileges:** the GUI runs as you; one small root helper does the
  changes through PolicyKit, with one action per operation, validated arguments
  and never a shell string. Changes ask for the administrator password every time.

Every view, the safety model and the limitations are described in detail in the
[NIRUSEC guide](docs/GUIDE.md).

## Requirements

- Debian, Arch or Void Linux (glibc), x86_64, X11 with OpenGL.
- `sudo` for installation, PolicyKit (`pkexec`) at runtime.
- UFW. The installer installs it as a dependency but **does not enable it**.
- Optional: Tailscale, Docker, `fwupd`.

## Installation

### With NIRUX

```sh
nirux extras install nirusec
nirux extras update            # later, for the extras you selected
```

NIRUX downloads the pinned release tag, verifies it and runs NIRUSEC's own
installer, which fetches the prebuilt binary; nothing is compiled. In NIRUX,
`nirux manual nirusec` opens the short tour in the NIRUX manual.

### Standalone

Run the installer as your desktop user, **not** with `sudo`; it asks for sudo
only to install the root helper and the PolicyKit action.

```sh
tar -xzf nirusec-0.2.0-x86_64-linux-gnu.tar.gz    # from the GitHub release
./install.sh
```

From a Git checkout, `./install.sh` downloads the prebuilt binary for the
version in `Cargo.toml` and verifies it against the release `SHA256SUMS`.

| Option | Effect |
|---|---|
| `--prebuilt` | Use `./nirusec` beside the script |
| `--build` | Build from this checkout with Cargo (development only) |
| `--no-deps` | Do not install runtime packages |

`NIRUSEC_PREFIX` (default `~/.local`) and `NIRUSEC_VERSION` override the
prefix and the version.

## Usage

Start **NIRUSEC** from NIRU Launcher, from the NIRUBAR shield, or:

```sh
nirusec                                  # GUI
nirusec --open firewall                  # overview, firewall, ports, logs, updates, firmware, docker
nirusec --check [--if-stale SECONDS] [--quiet]   # refresh the shared status cache
nirusec --status [--json]                # print the cache
nirusec --profile-rules soft             # exact UFW rules of soft, medium, hard or gaming
nirusec --profile-state                  # the recorded firewall profile state
nirusec --version
```

`--check` is short-lived on purpose. NIRUBAR runs it only when the cache is
stale, so a running bar never starts package queries every second.

Emergency recovery from a local console:

```sh
sudo /usr/local/libexec/nirusec-helper safe-mode     # emergency safe mode
sudo /usr/local/libexec/nirusec-helper restore-ufw   # restore the latest NIRUSEC backup
```

See [Emergency access](docs/EMERGENCY.md).

## Configuration

There is no user configuration file. Profiles are documented in
[Profile design](docs/PROFILES.md); per-machine local exceptions are made in the
Firewall view and stored root-owned in `/etc/nirusec/local-exceptions.toml`.
They are never part of Git, releases or the user cache, and every profile
preview shows them.

## Files and paths

| Path | Purpose |
|---|---|
| `~/.local/bin/nirusec` | GUI and checker |
| `/usr/local/libexec/nirusec-helper` | Root helper (the same binary) |
| `/usr/share/polkit-1/actions/se.nirucon.nirusec.policy` | PolicyKit actions |
| `${XDG_STATE_HOME:-~/.local/state}/nirusec/status.json` | Shared status cache read by NIRUBAR |
| `/var/lib/nirusec/` | NIRUSEC state (public state 0644, history and transactions 0600) |
| `/var/backups/nirusec/` | Root-only firewall backups (20 kept) |
| `/etc/nirusec/` | Local exceptions and settings (root) |

## Troubleshooting

- **Authentication fails right after install:** PolicyKit may not have loaded
  the new actions yet; log out and back in.
- **A firewall change cut my access:** do nothing; without **Keep** it is undone
  after 120 seconds. Otherwise use the emergency commands above.
- **Docker ports are reachable despite the firewall:** Docker published ports
  bypass UFW. Bind them to `127.0.0.1` or the Tailscale address.
- **No blocked-traffic data:** the UFW log is not readable or logging is off;
  NIRUSEC says so rather than showing zero.

## Uninstall

With NIRUX: `nirux extras uninstall nirusec` runs the uninstaller below from the pinned release.

```sh
./uninstall.sh
```

This removes the GUI, the root helper and the PolicyKit action. Firewall rules,
`/var/lib/nirusec`, `/var/backups/nirusec`, `/etc/nirusec` and the cache are
kept. It refuses while a firewall change is still waiting for Keep or Undo.

## Building from source

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --locked
sudo tests/netns/run.sh target/release/nirusec        # real UFW in an isolated namespace
tests/gui/run-xvfb.sh target/release/nirusec shots    # Xvfb screenshots
./install.sh --build                                  # local development install
```

`tests/netns/run.sh` runs the real UFW and the helper in a private network and
mount namespace; the host firewall and files are never touched. Use
`NIRUSEC_HELPER=/path/to/nirusec` only in a disposable environment: the GUI then
runs that helper instead of `pkexec`.

More: [Roadmap](ROADMAP.md), [0.2 review](docs/REVIEW-0.2.md),
[acceptance record](docs/ACCEPTANCE.md), [Fail2ban guidance](docs/FAIL2BAN.md).

## Status, disclaimer and how it's made

**Status: alpha.** The firewall core, safe undo and helper are tested in isolated namespaces and on my machines; fail2ban, outgoing rules and some update/firmware paths are not done yet. It changes your firewall, so read the previews.

NIRUX and every niru* project are made by me, Nicklas Rudolfsson
([@nirucon](https://github.com/nirucon)), for me. They are tailored to my own
needs, preferences and workflows, on my own machines. If they fit yours too,
that's a nice bonus.

- **Free and open source.** Anyone is free to use, study, change and share
  it under the [MIT License](LICENSE).
- **No guarantees.** There is no warranty of any kind. Use it at your own
  risk, read what you install and keep backups of anything that matters.
- **How it's made.** Some of these projects I built from scratch by hand. In
  more recent releases I have used Claude, Anthropic's AI, to do much of the
  heavy lifting under my direction: I decide what to build and how it should
  behave, and I test it on my own machines. It saves me a lot of time, and
  the result is quite OK.
- **Alpha, beta, dev, and maybe forever.** Most things here are alpha, beta
  or dev, and may stay that way. Maybe one day there will be a real stable
  release, but given how fast development moves, and how I am as a person,
  maybe never :)

| Label | Meaning |
|---|---|
| dev | Under active construction; may not build, install or work yet. |
| alpha | Works on my machines, but incomplete or rough; expect breaking changes. |
| beta | In daily use on my machines and mostly complete; rough edges remain. |

## License

MIT License, see [LICENSE](LICENSE). Copyright (c) 2026 Nicklas Rudolfsson.
