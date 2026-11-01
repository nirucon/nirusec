# NIRUSEC acceptance checklist

Status: **not started**. Fill this with evidence during implementation.
Use `pass`, `fail`, `not tested` or `unsupported` and explain the latter two.

## Platform matrix

| Platform | Release launches | Dependencies/install | Firewall | Updates | Firmware discovery | Scheduling | Resource soak |
|---|---|---|---|---|---|---|---|
| Arch Linux / systemd | not tested | not tested | not tested | not tested | not tested | not tested | not tested |
| Debian / systemd | not tested | not tested | not tested | not tested | not tested | not tested | not tested |
| Void Linux / runit | not tested | not tested | not tested | not tested | not tested | not tested | not tested |

Record OS/version, kernel, CPU/RAM/GPU, libc, display/scale, WM, relevant package
versions, artifact checksum and source commit for every actual test host.

## Functional gates

- [ ] Overview uses real facts and displays timestamps, errors and capability gaps.
- [ ] UFW IPv4/IPv6/default/logging/profile/rule operations work and preserve order.
- [ ] Stale rule IDs/conflicting changes cannot delete or edit the wrong rule.
- [ ] Other firewall managers are detected and preserved.
- [ ] SSH/Tailscale connectivity-aware rollback survives frontend exit/disconnect.
- [ ] Socket/process views distinguish local/LAN/Tailscale/wildcard bindings.
- [ ] Logs and graphs handle disabled logging, permissions, rotation and large files.
- [ ] System updates use supported APT/pacman/XBPS transactions and show failures.
- [ ] Security-only metadata is labelled honestly on all platforms.
- [ ] Firmware packages, microcode and device flashing are separate workflows.
- [ ] fwupd unsupported/no-update/error/power/reboot cases are handled truthfully.
- [ ] Real flashing only occurs on explicitly chosen supported test hardware.
- [ ] GUI is unprivileged; unauthorized/invalid helper requests are rejected.
- [ ] Critical notifications are transition-based, themed and deduplicated.
- [ ] Multiple NIRUBAR monitors read one cache and do not duplicate checks.
- [ ] Installer/update/uninstaller preserve existing firewall and user data.
- [ ] Offline/missing dependency/locked package database states stay recoverable.

## Interface gates

- [ ] 420, 640, 960 and 1440 logical-pixel layouts verified with screenshots.
- [ ] Laptop half/third tiling and small window heights work.
- [ ] 100/125/150/200% scale, long labels and IPv6 text remain usable.
- [ ] All built-in NIRUX themes plus a sparse custom theme are verified.
- [ ] Existing surfaces update live on theme changes; standalone fallback works.
- [ ] Keyboard navigation, visible focus and text-input shortcut isolation work.
- [ ] Charts have real units/time windows and readable empty/error states.

## Resource/lifecycle gates

- [ ] Release build measured against an idle baseline, including Xorg/compositor.
- [ ] GUI idle has no continuous redraw or expensive polling.
- [ ] Checker exits, does not overlap and respects configured intervals/power policy.
- [ ] 100+ repeated refresh/theme/resize/view cycles plateau in RSS/FD/thread use.
- [ ] Sustained log/chart/close/reopen tests show bounded storage and caches.
- [ ] Child processes are reaped; failure/timeouts leave no orphan workers.
- [ ] No repeated notifications, subprocess storm or per-monitor duplicate services.
- [ ] Shutdown/update/uninstall remove only owned scheduling/helper resources.

## Deployment record

| Owner-authorized target | OS/libc | Installed/running versions | Verification evidence | Pending work |
|---|---|---|---|---|
| Not yet specified | — | — | — | Owner supplies targets/access when implementation starts |

Do not mark sleeping/offline machines complete. Keep credentials and private
network details out of this public record.

## 0.1.4 live deployment run — 2026-11-01

Artifact: NIRUSEC 0.1.4, one x86_64 glibc binary. NIRUX 0.12.169,
NIRUWM 0.16.153, NIRUBAR 0.18.74.

| Machine | Distro | Installed | Cache/checker | UFW helper | GUI launch | Bar entry |
|---|---|---|---|---|---|---|
| studio | Debian | 0.1.4 | pass | pass (`Status: inactive`) | pass, tiled live X11 | pass, shield left of Quick Settings |
| othala | Debian | 0.1.4 | pass | pass (`Status: inactive`) | not run live | config present |
| niruxwork | Debian | 0.1.4 | pass | pass (`Status: inactive`) | not run live | config present |
| void | Void | 0.1.4 | pass | pass (active rules returned) | not run live | config present |
| algiz | Arch | 0.1.4 | pass | pass (active rules returned) | not run live | config present |
| ingwaz | Debian | 0.1.4 | pass | pass (`Status: inactive`) | not run live | config present |

Live GUI verification used the installed release on studio. Narrow (single-view)
and wide (navigation + detail) layouts were exercised under Xvfb at 420 and
1200 logical pixels before deployment. The installed GUI was also launched in
the tiled NIRUWM session. Idle release process observation: ~0.7% CPU, ~85 MB
RSS, 7 threads; no continuous redraws were observed. No zombies were present
after deployment checks.

UFW was installed as a dependency but was intentionally **not enabled**; four
machines therefore report `critical` because UFW is inactive while sockets are
exposed. This is a real state, not a fabricated result. The owner must review
and enable/configure UFW explicitly. The initial critical transition check is
suppressed when no previous cache exists, then deduplicated after the first
known state.

Not claimed as tested in this run: adding/deleting real firewall rules through
the GUI’s PolicyKit prompt, package installation/upgrade, actual fwupd device
flashing, connectivity rollback on every distro, long-duration soak beyond the
observations above, and every NIRUX theme. These remain implementation gates;
the helper’s UFW read path and validation tests passed, but privileged GUI
authentication and destructive update/firmware paths were not exercised.

## 0.1.5 recovery and roaming pass — 2026-11-01

- NIRUSEC 0.1.5 is installed on all six owner machines.
- `niruxwork`: UFW active with loopback, `tailscale0`, `virbr0`, home-LAN
  SSH/DHCP, Tailscale direct UDP 41641 and an additional USB Wi-Fi SSH/DHCP
  interface rule.
- A real safe-mode/restore cycle was performed on `niruxwork`: UFW was backed
  up to `/var/backups/nirusec/ufw-*`, safe mode made SSH and Tailscale reachable,
  then the previous rules were restored and NIRUSEC returned to `state: ok`.
- New SSH through Tailscale and Tailscale-direct connectivity were re-tested
  after enabling UFW; NIRUSHARE's Tailscale port was reachable.
- No zombies were observed during the final checks.

The additional workplace Wi-Fi workflow was not exercised in this pass. Device
firmware flashing, package upgrades and fail2ban changes were not performed.

## 0.1.7 profile/PolicyKit pass — 2026-11-01

- `pkexec`/PolicyKit is now a documented installer dependency and is present on
  all six machines. The earlier rule-load failure was a missing `pkexec`.
- NIRUSEC 0.1.7 with Off/Soft/Medium/Hard/Gaming profiles is installed on all
  six machines.
- Soft profile apply → new SSH through Tailscale → confirm → restore previous
  UFW files was exercised on `niruxwork`. The 120-second automatic rollback
  watchdog is armed by the same apply path; the full two-minute timeout was not
  waited for in this pass.
- Current `niruxwork` custom rules, including its USB Wi-Fi interface rule,
  were restored after the test. Home-LAN and Tailscale access remained usable.
- Workplace-network documentation was removed from the public repository; no
  current public file names the private network.

## 0.1.8 profile transaction and GUI pass — 2026-11-01

Artifact: NIRUSEC 0.1.8, one x86_64 glibc binary. Tested on `niruxwork` with
the new helper and PolicyKit action installed. `pkaction` loaded
`se.nirucon.nirusec.manage` after the corrected `<annotate>` policy file.

- Profile apply: backup included `/etc/ufw` and `/etc/default/ufw`; the pre-test
  home-LAN and USB-Wi-Fi rules were present in the backup. The state file showed
  `pending` with a 120-second deadline.
- A new SSH session through Tailscale succeeded while the profile was pending.
- `profile-confirm` changed the state to `kept` and removed the transaction
  token. The global GUI banner and profile card are designed around this state.
- Automatic rollback was tested by applying Soft and waiting the full 120
  seconds without confirming. The watchdog restored the exact pre-test custom
  rules, including the USB interface rules, and kept UFW enabled because
  `previous_enabled` was true. State became `rolled_back`.
- A real rule was added with source, protocol, port and comment, then deleted
  using a freshly loaded rule number plus the expected raw rule text. UFW
  reported the correct rule before deletion and no test rule remained.
- The 0.1.8 NIRUSEC GUI was visually launched on `studio` under the live X11
  display; the Firewall view showed the global active-profile banner, profile
  cards and policy actions without clipping at the available desktop size.
- A second transaction was tested on `studio`, where UFW was already inactive:
  Off profile → confirm → restore kept `ENABLED=no` and `Status: inactive`.
  A previously disabled firewall is therefore not silently enabled.
- The release tarball installer was run on `niruxwork` and `studio` with
  `--no-deps`; local SHA-256 verification passed and the PolicyKit action loaded.
- Not tested in this pass: full GUI PolicyKit authentication through the desktop
  agent (the helper and policy were tested directly), narrow tiling screenshots,
  actual firmware flashing and full package-manager upgrades.
