# NIRUSEC roadmap and remaining work

Status after **0.1.8** (2026-11-01). This is a working list, not a promise that
every item belongs in the next release. Security and access-affecting items come
before cosmetic work.

## P0 — do next

### Persist the active profile across reboot

Current limitation: the confirmed profile state lives in `/run/nirusec/profile.json`.
UFW rules survive a reboot, but the GUI can show **Custom** after a full reboot
because `/run` is a tmpfs.

Recommended design:

- [ ] Write confirmed/current profile state to `/var/lib/nirusec/profile.json`
      with directory `0755` and file `0644`; it contains no credentials.
- [ ] Keep pending transaction metadata, the watchdog script and the firewall
      lock in `/run/nirusec`.
- [ ] Read the persistent state first and fall back to the old `/run` path for
      migration; migrate once on the next successful profile apply.
- [ ] Do not persist a `pending` transaction as the active profile. If a pending
      transaction existed at shutdown, mark it **interrupted** after boot and
      show a prominent warning; the rollback timer cannot be trusted across a
      reboot.
- [ ] Refuse a new profile apply while an interrupted transaction is unresolved.
- [ ] Add a live reboot test: apply Soft → confirm → reboot → verify UFW rules,
      active-profile banner, no stale pending token and no leftover watchdog.
- [ ] Release the change and update the NIRUX extra pin only after that test.

### Verify the active profile more strongly

- [ ] Store a root-owned snapshot/hash of the applied UFW configuration at
      confirm time and verify it during an authenticated refresh.
- [ ] Keep the current unprivileged timestamp check as a fast local hint, but do
      not label a profile “verified” when only timestamps were checked.
- [ ] Clearly distinguish external edits, interrupted transactions, manual edits
      and intentional Off.

### Safe local exceptions for specific machines

Needed so a machine-specific interface, subnet or management path can survive a
profile reset without publishing private network details.

- [ ] Local-only exception file owned by root, outside Git.
- [ ] Validate interface names, addresses and ports before applying.
- [ ] Show local exceptions in the profile preview and active-profile details.
- [ ] Never upload or include the local exception file in diagnostics/releases.
- [ ] Test that a profile apply reports exactly which local exceptions are kept
      or removed.

### Full GUI/PolicyKit and recovery verification

- [ ] Exercise Keep, Restore now, failed confirmation and expired countdown from
      the real desktop GUI, not only the helper.
- [ ] Test opening NIRUSEC from NIRUBAR, the application menu and a fresh login.
- [ ] Test safe mode and restore of a specific historical backup with the 0.1.8
      backup layout.
- [ ] Test a pending transaction at logout, GUI crash and forced kill.
- [ ] Add a visible recovery path if the helper or PolicyKit agent disappears.

### Firmware safety before broader use

- [ ] Do not offer a firmware action without a selected device and visible
      current/new version.
- [ ] Enforce AC/battery, dock/USB, reboot and recovery prerequisites from fwupd
      flags where available.
- [ ] Separate metadata refresh from flashing.
- [ ] Test no-update, unsupported, low-battery, locked and interrupted cases.
- [ ] Perform a real supported device flash only on explicitly chosen hardware.
- [ ] Do not claim rollback unless the device/fwupd actually provides it.

## P1 — important improvements

### Firewall and profiles

- [ ] Preview a profile diff before applying: added, removed and retained rules.
- [ ] Define a real difference between Medium and Hard, or merge them.
- [ ] Give Gaming an explicit duration and automatic return to the previous
      profile, surviving GUI exit.
- [ ] Add a one-click “restore this specific backup” list instead of only latest.
- [ ] Preserve/restore exact directory contents, including removal of stale
      `applications.d` entries, without deleting unrelated files.
- [ ] Add a shared UFW operation lock for all write paths, not only profiles.
- [ ] Add an audit history of profile changes, rule changes, restores and
      failures with bounded retention and useful command results.
- [ ] Add a persistent result panel with copy/export of privileged output.
- [ ] Make the profile buttons and active banner remain usable during status
      refresh without consuming the rollback window.

### Access and diagnostics

- [ ] Show the likely management path before a profile change: current SSH
      interfaces, Tailscale state and which profile rule would preserve access.
- [ ] Add “Why is this port reachable?” combining listening socket, binding,
      UFW rule and Docker port publishing, with explicit unknowns.
- [ ] Add opt-in temporary openings with a visible expiry and root watchdog.
- [ ] Add a redacted diagnostic report by default; make hostnames, IPs, paths
      and process names opt-in.
- [ ] Document that a GUI launched from a detached SSH session is not an active
      seat session and PolicyKit will deny it.

### Updates and firmware

- [ ] Refresh package metadata before presenting an install preview, or label
      that the preview may change.
- [ ] Show package-manager output and reboot requirement in the GUI, not only
      stderr/logs.
- [ ] Handle Arch/APT/XBPS lock, signature, conffile and partial-failure paths
      with clearer states.
- [ ] Add a consistent XBPS self-update/full-update sequence on Void.
- [ ] Improve hardware-to-firmware package mapping and Debian non-free
      availability detection.
- [ ] Keep the per-device fwupd list, but add release notes, size, power and
      reboot requirements before confirmation.

## P2 — polish and broader validation

- [ ] Add search/filter for rules, ports, packages and containers.
- [ ] Make Overview cards open the relevant view.
- [ ] Add active-profile and data-age details to the NIRUBAR tooltip.
- [ ] Add NIRULAUNCHER actions/deep links for firewall, updates and firmware.
- [ ] Add web links for safe NIRUX documentation from the relevant views.
- [ ] Verify 420/640/960/1440 logical-pixel layouts, half/third tiling, small
      heights and 100/125/150/200% scaling with screenshots.
- [ ] Verify every built-in NIRUX theme and a sparse custom theme live.
- [ ] Run a sustained idle/refresh/theme/resize/open-close soak on release
      builds, including child-process and file-descriptor counts.
- [ ] Complete live matrix testing on Arch, Debian and Void for helper,
      PolicyKit, logs, updates, firmware discovery and UFW variants.
- [ ] Add automated tests for profile state persistence, interrupted
      transactions, policy-file parsing and stale rule deletion.

## Release/deployment rules for the remaining work

- Do not claim firmware flashing, full package upgrades or every PolicyKit path
  has been tested until there is live evidence in `docs/ACCEPTANCE.md`.
- Keep private network details and machine-specific exceptions out of public
  files, issues, release assets and Git history.
- Preserve the current working NIRUX generation and one rollback generation when
  publishing new pins.
- Clean temporary credentials, test rules, auth files and watchdogs after every
  deployment pass.
