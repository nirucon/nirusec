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
