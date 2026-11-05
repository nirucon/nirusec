# NIRUSEC 0.2 review — firewall, privilege boundary and usability

Scope: NIRUSEC 0.1.8 (commit `6190860`) as a NIRUX front end for UFW. The
review covers the PolicyKit/root-helper boundary, firewall correctness
(lock-out, IPv6 parity, Tailscale/SSH reachability, atomic apply/rollback,
reboot persistence) and how understandable the firewall view is for someone
who does not read UFW output. Updates and firmware were checked for cheap,
safe fixes only.

Every finding marked *reproduced* was shown on 0.1.8 inside an isolated
network + mount namespace (`unshare --net --mount`, overlay `/etc`, private
`/run` and `/var`) with veth peers for LAN, internet and `tailscale0`. The
host firewalls were not touched. The 0.2 behaviour is covered by
`tests/netns/run.sh` (99 checks, run on Debian 13, Arch and Void) and by unit
tests.

## Threat model

* The GUI runs as the desktop user. The only privileged code is
  `/usr/local/libexec/nirusec-helper` (same binary, helper mode), started by
  `pkexec` with a clean environment.
* An attacker is any other program running as the same user in the active
  session (a browser exploit, a malicious script). It can run
  `pkexec /usr/local/libexec/nirusec-helper …` with arbitrary arguments, but it
  cannot type the administrator password.
* Other local users and inactive/remote sessions get nothing (`allow_any` and
  `allow_inactive` are `no`).

## Findings (ranked)

| # | Severity | Area | Finding | Evidence | 0.2.0 |
|---|---|---|---|---|---|
| C1 | Critical | Firewall | Applying a profile ran `ufw --force reset`, which **switches the firewall off for the whole apply** (8.5 s measured). A port that no profile allows was reachable from the LAN in 36 of 40 probes during a Soft apply. | reproduced (R1) | **Fixed.** Profiles are built in a staging copy inside a private mount + network namespace, the finished files are swapped in and loaded with `iptables-restore -n` (one table commit per family, fail-closed). 0 of ~240 probes reached the closed port during an apply (T1); the resulting netfilter state equals `ufw reload` (T11). |
| S1 | High | Privilege | One PolicyKit action with `auth_admin_keep` covered *every* operation. After the user typed the password once (even just to read rules), any program running as the user could silently disable the firewall, open ports, run a full system upgrade or **flash device firmware** for about five minutes. | policy file + PolicyKit semantics | **Fixed.** Separate actions selected by `exec.argv1`: firewall changes, updates, firmware install and firmware flashing need `auth_admin` *every time*; reading status is allowed for the active local session only; Keep/Undo of a pending change need a 128-bit token that only the GUI which started the change received. |
| S8 | High | Privilege | (Found while implementing S1.) pkexec maps a call to the **first** action, in polkitd's enumeration order, whose `exec.path` matches and whose `exec.argv1` matches *or is unset*. A path-only “catch-all” action can therefore shadow specific actions: on othala `tx-undo` was mapped to the catch-all and asked for a password while `tx-confirm` was not. | reproduced natively (polkit 126, othala) and in pkexec source | **Fixed.** Every action names its argv1 and there is no catch-all; unknown operations fall back to `org.freedesktop.policykit.exec` (admin password) and are rejected by the helper. A test guards the policy file. |
| C2 | High | Firewall | `ufw reset` replaced customised `before*.rules`/`after*.rules` with package defaults (e.g. NAT or Docker rules) and left six `*.rules.YYYYMMDD_HHMMSS` copies in `/etc/ufw` per apply. | reproduced (R2) | **Fixed.** Only user rules, default policies and the matching log prefixes are replaced (T1). |
| C3 | High | Persistence | Profile and pending-change state lived in `/run` (tmpfs). A reboot during the rollback window left the **unconfirmed profile active with no watchdog and no record**; after any reboot the GUI showed “Custom”. | reproduced (R5) | **Fixed.** State in `/var/lib/nirusec` (0644, no secrets; transaction records 0600). A pending change from an earlier boot (boot id) is shown as *interrupted*, blocks new changes and can be kept or restored (T5). 0.1.8 state is migrated (T14). |
| C4 | High | Recovery | Emergency safe mode via the documented `sudo …/nirusec-helper safe-mode` was **refused while a change was pending or had failed to roll back** — exactly when it is needed. | reproduced (R3) | **Fixed.** Safe mode always runs, cancels pending changes and their watchdogs (T8). |
| C5 | High | IPv6 | Deleting a rule removed only the IPv4 half; the IPv6 twin stayed open (port 8080 still reachable over IPv6). | reproduced (R4) | **Fixed.** The GUI shows one row per rule and deletes both halves after checking both are unchanged (T6). |
| C7 | High | Lock-out | “Enable firewall” had no rollback or warning; with default deny and no SSH rule it cut LAN SSH. | reproduced (R11) | **Fixed.** Turning UFW on, block rules, removing allow rules, default-policy changes and restoring old backups all get the rollback window and a remote-access estimate (T7, T12, T13). |
| U1 | High | GUI | Keep/Restore shared one busy flag with the status check, so a slow update check could **use up the rollback window**. | code + timing | **Fixed.** Separate flags; the banner stays usable during refreshes. |
| S3 | Medium | Privilege | Confirmation token was predictable (pid + nanoseconds) and published in world-readable `/run/nirusec/profile.json`. | reproduced (R7) | **Fixed.** Random token, never in public state (T1). |
| S4 | Medium | Privilege | Helper accepted extra arguments; `ufw-delete N` without the expected text deleted by **stale rule number**; `firmware-update` without a device updated *all* devices. | reproduced (R10) | **Fixed.** Exact arity for every operation; delete requires the exact rule text; firmware flashing requires a selected device (T9). |
| S2 | Medium | Privilege | The password prompt only said “Manage firewall, updates and firmware”. | policy file | **Fixed.** Specific messages per action. |
| C6 | Medium | IPv6 | Soft/Gaming LAN rules were IPv4-only (SSH from the IPv6 LAN blocked). | reproduced (R16) | **Fixed.** `fd00::/8` and `fe80::/10` added when UFW IPv6 is on (T1). |
| C8 | Medium | Firewall | Block rules were appended after allow rules (often ineffective) and had no rollback. | code + T7 | **Fixed.** Blocks are prepended and windowed. |
| C9 | Medium | Firewall | Only profiles took the lock; safe mode, restore and rule edits did not; delete had a check/delete race. | code | **Fixed.** One lock for every write; delete re-checks under the lock. |
| C10 | Medium | Rollback | The watchdog was `setsid sh` inside the user's session. | code | **Fixed.** Transient systemd timer in the system manager on Debian/Arch; detached root process on runit. |
| C11 | Medium | Rollback | Restoring a backup disabled UFW while copying files. | code | **Fixed.** Changed files are installed atomically and reloaded without switching off. |
| C12 | Medium | Verification | “Verified profile” relied on file timestamps only. | code | **Fixed.** Root snapshot of the UFW files at each NIRUSEC change; the status check reports *verified* or *changed outside NIRUSEC* with the file list (T1, T2). |
| C13 | Medium | Persistence | Firewall “Active” came from `ufw.conf`; whether UFW starts at boot was never checked. | code | **Fixed.** Runtime state from `ufw status`; boot service check (systemd/runit) with a warning; turning the firewall on enables the boot service. |
| S7 | Medium | Validation | “Any port from anywhere” produced invalid `ufw allow`; `allow proto tcp` failed. | reproduced (R9) | **Fixed.** Rejected with an explanation. |
| U3 | Medium | GUI | No plain-language status; profile names without meaning; rules applied without preview or confirmation; raw UFW text; “Disable” without undo. | screenshots | **Fixed.** “Protected — incoming connections are blocked, except: …”, profile purposes, a preset rule editor with exact command preview, confirmation dialogs with remote-access warnings, history with restore. |
| F1 | Medium | Updates | Debian `apt-get upgrade` ran with stdin closed and failed on conffile prompts. | dpkg behaviour | **Fixed.** `--force-confdef --force-confold` (keeps local configuration). |
| U2 | Low | Energy | An expired/failed state repainted once per second forever. | code | **Fixed.** The 1 Hz tick only runs during the window plus 30 s. |
| U5 | Low | GUI | PolicyKit failures showed raw exit text. | code | **Fixed.** Explains a cancelled/refused prompt and the console recovery command. |
| S5 | Low | Privilege | Children inherited the environment and were found via `PATH`. | code | **Fixed.** Absolute UFW path, `env_clear`, fixed `PATH`/`LC_ALL`, umask 022. |
| S6 | Low | Validation | Comments allowed quotes and leading `-`, which UFW rejects with a usage dump. | reproduced (R9) | **Fixed.** Allow-list of characters, 64 chars. |
| C14 | Low | Profiles | Medium and Hard were identical. | docs | **Fixed.** Hard also closes Tailscale direct UDP and DHCP; Medium keeps them. |
| C15 | Low | Energy | Every unprivileged check spawned `ufw status`, which always fails without root. | code | **Fixed.** Skipped. |
| B1 | Medium | Build | `rust-version = "1.85"`, but the 0.1.8 `Cargo.lock` needed rustc 1.86–1.88 (calloop 0.14.5, icu 2.4, image 0.25.10, wayland-protocols 0.32.13), so `--locked` failed on Debian 13's rustc 1.85. | reproduced (`cargo +1.85 build --locked`) | **Fixed.** Lockfile pinned to 1.85-compatible versions; CI builds and tests on 1.85. |
| D1 | Low | Updates | Void XBPS should update `xbps` itself first. | docs | **Deferred** — needs a live Void run with a pending xbps update. |
| D2 | Low | Energy | Theme watcher stats files every 2 s (pre-existing; repaints only on change). | measured 0.0 % CPU | **Deferred** — negligible; inotify would add a dependency. |
| D3 | Info | Firewall | Docker-published ports bypass UFW. | known | Documented (unchanged). |

## What a local program can make the helper do (0.2.0)

| Operation | Without password (active session) | Notes |
|---|---|---|
| `ufw-status` | yes | Read-only. No arguments accepted. Returns rules, change history and local exceptions. |
| `tx-confirm TOKEN`, `tx-undo TOKEN` | yes | Only with the random token of a *pending* change, which only the starting GUI received. Worst case: keep or undo a change the user just authorised. |
| Everything else | no — `auth_admin` every time | Rule/profile changes, enable/disable, safe mode, restore, updates, firmware. |

Inactive sessions and other users: nothing without administrator
authentication (`allow_any=no`, `allow_inactive=no`).

## Native verification (2026-11-05, candidate 0.2.0)

Each host: exact UFW state saved, a 5-minute dead-man switch armed (systemd
timer, or a detached root job on Void), a second SSH session kept open, and a
fresh SSH connection over Tailscale from another machine checked after every
step. The candidate helper ran from a root-only temporary directory with a
30 s rollback window.

| Host | Before | Soft → Keep → verified | Hard not kept → automatic restore | Block rule → Undo | Restore diff |
|---|---|---|---|---|---|
| othala (Debian 13, systemd) | UFW inactive | pass (systemd timer armed/stopped) | pass (timer fired, Soft back) | pass | empty (after removing the empty `ufw-*` skeleton chains that `ufw disable` leaves on a host that booted with UFW off) |
| algiz (Arch, systemd) | active, deny in, 22/tcp | pass | pass | pass | empty |
| void (Void, runit/elogind) | active, 22/tcp, tailscale0, 41641/udp | pass (detached watchdog) | pass | pass | empty |

PolicyKit (othala, polkit 126, real seat session 1428, test copy of the
policy with separate action ids): `ufw-status`, `tx-confirm`, `tx-undo` ran
without a password; `pkcheck` without interaction returned *authentication
required* for every change, update and firmware action.

## Verification evidence

* `cargo test`: unit tests for parsing, validation, argument building,
  twins, plain-language descriptions, reachability estimates, profiles and
  exceptions, token/backup-name confinement.
* `tests/netns/run.sh`: 99 checks per distro — Debian 13 (ufw 0.36.2,
  iptables-nft), Arch and Void — all passing. Reproductions of the 0.1.8
  findings used the same harness with the 0.1.8 helper.
* GUI: Xvfb screenshots at 420/640/960/1200 px with a fixture helper
  (`tests/gui/`); idle CPU 0.0 % (0.1.8: 0.0 %) over 60 s.
