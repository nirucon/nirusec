# NIRUSEC — end-to-end implementation assignment

## Mission

Build NIRUSEC into a real, polished, installable Rust GUI for the NIRUX suite.
Implement the product described in README.md, verify it on authorized bare-metal
targets across Arch Linux, Debian and Void Linux, then package, release and
deploy it on the machines the owner names for this assignment.

This is an instruction to finish the product, not produce another specification,
mock dashboard or collection of buttons that print commands. Continue through
implementation, integration, bug fixing, release packaging and live validation.
Do not claim perfection or absence of leaks without evidence; distinguish
implemented, automatically tested and live-verified behaviour.

## Current starting state

The 0.1.0 core implementation is present in this repository. It is the starting
baseline, not a claim of completed acceptance: continue with hardening, missing
edge cases, live matrix verification and the deployment gates below. Keep the
project status honest as work progresses.

Read this file, README.md and docs/ACCEPTANCE.md before editing. Check local
changes, repository status, branch and existing releases before proceeding.
Preserve unfamiliar user work.

## Owner context and deployment authorization

- Product owner: Nicklas Rudolfsson; GitHub namespace: `nirucon`.
- Desktop: NIRUX/NIRUWM, usually tiling, including narrow laptop layouts.
- Supported platforms: x86_64 Arch Linux, Debian and Void Linux/glibc. Detect
  libc/architecture; do not advertise a glibc binary as musl-compatible.
- Common fleet names from earlier work are studio, othala, niruxwork, void,
  algiz and ingwaz-deb. **This list is context, not a live deployment target
  list.** The owner will specify machines and access when starting this repo.
- Use only the targets and access supplied/authorized for that implementation
  session. Do not recover old passwords from unrelated files or commit secrets.
- Named bare-metal targets may be used for dependency installation, release
  builds, GUI tests, benchmarks and requested NIRUX integration/deployment.
- Inspect each target first: OS/version/libc, display manager, session,
  firewall/network state, package-manager locks, power/battery and installed
  firmware. Do not assume an earlier machine snapshot is still accurate.
- Routine reversible development and tests should proceed autonomously.
  Coordinate connectivity-disrupting operations, reboots and actual device
  firmware flashes with the owner. Do not reboot active work just to check a
  binary version. Use narrow service restarts when sufficient.
- If a target sleeps or goes offline, retain an explicit pending deployment
  item and report it. Never label an unreachable target updated or tested.

## Product scope: complete the core first

Deliver functional Overview, Firewall, Ports, Logs, Updates and Firmware views.
Include saved firewall profiles, bounded change history, diagnostics, installer,
uninstaller, CLI/cache interface and NIRUX integration. Core features must use
real system state; no random graphs, synthetic vulnerability counts or fake
security score. Mock services/fixtures are for tests only and visibly separated
from production operation.

Later extensions include richer SSH/Fail2ban status and local Tailscale views.
Do not let optional extensions delay completion of the core. Remote fleet
management, tailnet ACL administration, antivirus suites and packet inspection
are separate products unless explicitly added by the owner.

## Implementation approach

Prefer Rust with egui/eframe, building on lessons from NIRUAMP. Inspect current
suite repositories before choosing APIs or copying code. Use focused modules
for UI, models, theme resolution, firewall, sockets/logs, updates, firmware,
cache/checker, privilege boundary and platform adapters.

Use typed models and a versioned protocol between GUI/checker/helper. Keep
privileged code small, synchronous where practical and independently testable.
Do not build one giant main.rs containing UI, root commands and parsers.

All slow operations run off the GUI thread. Present progress, cancellation
semantics and actual command results without blocking X11 event handling.
Cancellation of a package-manager transaction must not blindly kill a package
database write; show which operations cannot be safely interrupted.

### Research existing suite capabilities first

Inspect `nirux`, `niruwm`/`niructl`, `nirubar`, `nirulauncher`, `nirunotify`,
`niruflow`, `niruamp` and any existing NIRUSEC-related tool before duplicating
logic. Look for canonical theme/input/update/status interfaces. Reuse supported
APIs or extract a focused common interface where justified; avoid introducing
an unrelated all-suite rewrite.

## Firewall correctness and connectivity

- UFW is the initial write backend; preserve its configuration, managed state,
  application profiles and IPv4/IPv6 semantics.
- Inventory nftables/iptables/firewalld/UFW state before making changes. A
  non-UFW setup should remain readable where possible and explicitly unsupported
  for writes, not be silently converted or overwritten.
- Run tools with explicit argument arrays and stable parsing locale. Prefer
  structured data when available. Isolate version-sensitive UFW parsing and test
  output variants across the three distros. Never assume a friendly text format
  is a permanent machine API.
- Validate IP addresses, CIDRs, protocols, ports/ranges, interfaces and profile
  identifiers. Preserve rule order; do not delete the wrong rule using a stale
  rule number. Re-read state and detect conflicts before committing edits.
- Identify current SSH peers, routes and Tailscale interface policy. A port
  listener alone does not prove public reachability or a vulnerability.
- For default-policy/profile/connectivity changes, stage an accurate backup and
  arm a privileged bounded rollback before applying. The rollback must survive
  a disconnected GUI, user logout and crash. Confirm/cancel it explicitly and
  test the failure path on an authorized machine with another access path.
- Do not temporarily flush the firewall while editing. Treat IPv6 deliberately;
  never claim protection after changing only the IPv4 view.
- Audit successful and failed changes with bounded retention and useful result
  details, without passwords, auth tokens or unrelated personal data.

## Privilege boundary

The main GUI must never require root. Use a root-owned helper and narrowly
scoped Polkit actions for operations such as applying a validated firewall
transaction, starting an approved update or requesting an available firmware
operation. Authenticate the actual caller over the chosen transport; do not
trust a user ID supplied inside a JSON request.

Use fixed trusted executable paths/lookup policy, explicit arguments, clean
environment, safe temporary files and strict input limits. Reject unknown
operations and unauthorized callers. Never accept shell strings, arbitrary
executables, unrestricted paths, unvalidated environment overrides or a generic
"run as root" action. Do not place credentials in argv, logs, source or cache.

Prefer read-only unprivileged observations where possible. Explain unavailable
process ownership/log details without demanding root for the entire overview.

## Updates: distro-native behaviour

Implement adapters with explicit capabilities, previews and errors:

- **Debian:** use APT's supported resolver and configured repository metadata to
  classify security-origin updates. Include dependency changes in the preview;
  never promise an exact security classification when metadata is unavailable.
  Surface repository/signature failures, conffile prompts and package locks.
- **Arch:** only offer a supported full `pacman -Syu` transaction for normal
  updating. Do not refresh databases and then install selected security packages
  as a partial upgrade. Advisory availability is distinct from update availability.
- **Void:** follow supported XBPS self-update/full-update sequencing. Handle
  package replacements and transaction results honestly; no invented security
  repository or complete security-only classification.

Reuse existing NIRUX/NIRUFLOW update infrastructure where sound. Prevent overlap
with external package managers and NIRUSEC operations. Never disable signature
verification, forcibly remove package locks or autoremove kernels just to make
a status check pass. Distinguish package updates, NIRUX core generations,
selected extras and device firmware; they have different update/rollback models.

## Firmware is part of NIRUSEC

Separate these workflows in code and UI:

1. Hardware-relevant distro firmware packages (GPU/Wi-Fi/Bluetooth/audio/SOF).
2. Appropriate Intel/AMD CPU microcode and reboot/activation information.
3. Actual BIOS/UEFI/device flashing through `fwupd` where supported.

Do not install every available firmware package. Discover hardware using
available standard interfaces, compare to installed distro packages and suggest
the relevant supported set. Explain why a recommendation applies and label
uncertain mappings. Example package families vary: Arch/Void use
`linux-firmware`, `sof-firmware`, `intel-ucode`/`amd-ucode` or split packages;
Debian uses packages such as `firmware-iwlwifi`, GPU-specific firmware,
`firmware-sof-signed`, `intel-microcode` and `amd64-microcode`. Verify names
against actual distro repositories instead of copying this illustrative list.

Detect Debian repository components and unavailable packages; do not silently
enable non-free/non-free-firmware or third-party feeds. Show an actionable remedy.
Touchpad tapping/scrolling are usually libinput/Xorg configuration, not firmware;
link to the existing NIRUX input settings instead of replacing input drivers or
duplicating those controls inside NIRUSEC.

For `fwupd`: discover capabilities, devices, configured remotes, available
updates, history and results. Separate metadata refresh from flashing. Preserve
the service's signature checks and vendor prerequisites. Expose AC/battery,
reboot, dock/USB and recovery requirements and require a deliberate final user
action for a real flash. Do not bypass low-battery checks or claim every BIOS
can be updated. Test discovery and no-update/unsupported/error cases without
flashing all test machines unnecessarily. Do not advertise device-flash rollback
unless the actual device/tool provides it.

## Responsive UI and NIRUX themes

Aim for an original, restrained NIRUX tool, not a stock dashboard. Use clear
hierarchy, compact spacing, useful icons, small charts and plain labels.

- At wide sizes use navigation + list + detail panel; at narrow sizes use a
  single view and clear Back navigation. Tables adapt to cards/compact rows.
- Test 420/640/960/1440 logical-pixel widths, half/third laptop tiling, small
  heights and 100/125/150/200% scaling. No clipped actions or essential horizontal
  scrolling. Long IPv6 addresses, package names and translations must fit/wrap.
- Support Tab/Shift+Tab, Enter, Escape, visible focus and useful shortcuts.
  Keyboard shortcuts must not steal input from editable fields.
- Follow active NIRUX built-in/custom themes, current appearance overrides,
  fonts, scale and reduced-motion settings with the suite's actual precedence.
  Live theme changes must update existing surfaces without restarting the GUI.
- Use text/icons as well as status colour. Critical states use the theme's
  semantic error colour, normally red; warning/stale/unknown states are distinct.
- Charts use real bounded log data, clearly labelled units/time windows and
  empty/error states. Refresh only visible charts; avoid idle animation.
- Provide a readable standalone fallback outside NIRUX. Do not hard-code home
  directories, monitor IDs, hostnames or theme palettes into production logic.

## NIRUBAR, NIRULAUNCHER and NIRUNOTIFY

Implement a documented CLI/JSON/cache contract for deep links and status.

- NIRUBAR: one icon, no permanent text; absent when not installed, theme-coloured
  normal state, warning/error roles as appropriate; tooltip includes state and
  data age. Click opens NIRUSEC. Reuse the same cache across monitors.
- NIRULAUNCHER: desktop entry plus native actions/deep links for overview,
  firewall, updates and firmware where the existing action architecture allows.
- NIRUNOTIFY is the notification service ("nirunotice" in the discussion meant
  NIRUNOTIFY). Send critical-urgency alerts for genuine policy-defined critical
  transitions, not every available update or an intentionally disabled firewall.
- Deduplicate state transitions and repeated failures. Respect DND and lock
  privacy; do not leak IP/process details on a locked screen or implement a
  second notification daemon. Use existing themed critical notification styling.
- The cached status must include schema, timestamps, source/error state and
  relevant capability flags. Failed checks never replace a valid timestamp with
  an apparently healthy fresh result.

## Performance and lifecycle — non-negotiable

Recent suite regressions included unreaped notification-sound children and a
CAVA lock screen that generated CopyArea `NoExposure` events and repainted at
hundreds of frames per second. Apply those lessons deliberately:

- No continuous redraw while idle. No polling loop awakened by its own render
  events. Disable unnecessary X11 graphics exposures if using CopyArea directly.
- GUI queries are async, bounded and cancellable where safe. Batch/coalesce
  changes and refresh only visible views; do not rerun expensive checks on resize.
- A short-lived scheduled checker writes one atomic versioned cache. No
  permanent per-monitor polling process and no package-manager network check
  every second. Intervals must be configurable, conservative and jittered.
- On Arch/Debian use verified systemd user/system timer ownership appropriate
  to the operation. On Void use a tested runit-compatible scheduling solution
  without silently enabling duplicate cron/timer services. Remove scheduling
  cleanly on uninstall and avoid network checks on battery where policy forbids.
- Cap log history, graph samples, audit storage, text, queues, worker count and
  concurrency. Support rotation/truncation of log sources and incremental reads.
- Every spawned child must be waited/reaped; drain stdout/stderr without deadlock.
  Add timeouts to read-only probes; bound and clean up helper processes on exit.
- Use one instance per user unless there is a tested multi-window reason. The
  checker/helper must not duplicate UFW/package-manager/firmware ownership.
- Measure release builds, not debug builds. Include descendants, checker,
  Xorg/compositor, open FDs, thread count, disk/cache growth and zombies.
- Compare quiet baseline, GUI idle, graph visible, repeated refreshes, theme
  changes, resize, close/reopen and update/error paths. Run sustained tests long
  enough to distinguish a bounded cache warming up from a leak.
- Initial idle goals: GUI CPU close to zero when unchanged; no GUI process after
  closing; checker terminates; repeated workloads plateau in memory/FD/thread
  use. Establish measured budgets with the actual release build instead of
  claiming universal numeric guarantees.

## Installation, release and suite ownership

- Provide a reproducible locked Rust build, runtime dependency mapping,
  install/update/uninstall scripts, desktop entry, original scalable icon,
  versioned release artifacts and SHA-256 checksums.
- Provision required runtime dependencies during installation on all three
  distros. Handle optional UFW/fwupd/logging/advisory capabilities explicitly.
  Installing the GUI must not activate a firewall or flash devices.
- Install root-owned helper/Polkit files with correct ownership/modes. Never
  weaken global sudo/Polkit rules. Do not store passwords in a helper config.
- Respect NIRUX-owned paths and record standalone ownership; do not overwrite
  unrelated display-manager, desktop or personal configuration.
- Add NIRUSEC as an explicitly selected NIRUX extra and wire bar/launcher APIs
  coherently. Inspect current release manifests and source-archive checksums;
  do not guess versions or reuse another application's checksum.
- Add CI for Rust format, Clippy, meaningful tests and release packaging. Test
  helper/parser/platform behaviour and dependency/install/uninstall failure
  paths. Keep no-op/reversible UI tests proportionate; prioritize risky behaviour.
- When the owner requests implementation/deployment, publish authorized focused
  releases and coordinated suite pins after tests pass. This brief alone does
  not authorize deleting unrelated projects, accounts, data or configurations.
- Clean superseded NIRUSEC/coordinated component releases using the owner's
  latest-plus-one policy, after checking retained NIRUX rollback manifests and
  references. Keep referenced assets available; do not blindly delete tags just
  because their version sorts lower. Preserve the current working generation
  and an operational rollback. Never force-move a published tag to repair a hash.

## Work phases and completion gates

1. **Inventory and decisions:** inspect repositories/targets, record supported
   capabilities and choose privilege/cache/scheduler contracts. Keep a real task
   list and proceed with implementation rather than stopping at the plan.
2. **Functional core:** real overview and read-only observations, then validated
   UFW transactions, profiles and privileged rollback.
3. **Updates and firmware:** finish distro adapters, runtime dependencies,
   metadata/power/error paths and deliberate device-update workflow.
4. **Polished GUI:** responsive tiling layouts, all themes/live reload, keyboard
   navigation, real log charts and clear unknown/stale states.
5. **Suite integration:** single cached bar icon, launcher actions, deduplicated
   critical notifications and clean schedule/ownership lifecycle.
6. **Verification:** unit/integration tests plus actual release builds on named
   bare-metal machines, including resource soak and connectivity rollback.
7. **Release and deployment:** verify artifact identities/checksums, publish
   authorized releases/pins, install on every named target and verify the
   running version, not only the downloaded binary. Use targeted restarts;
   reboot only when required/authorized.
8. **Close out:** update docs, acceptance matrix and measured results; clean
   temporary credentials, grants, test rules, units, helpers and superseded
   unreferenced releases. Leave no unrelated services/windows running.

Do not call the task complete until the acceptance checklist is satisfied or
specific genuine blockers are clearly recorded. A target being unreachable is
a deployment blocker, not a reason to fabricate a successful verification.

## Final report requirements

Report working features and limitations, frontend/helper/suite versions and
commits, release URLs, exact installation/run commands, supported distro/libc
matrix, named machines actually tested, screenshots at narrow/wide sizes,
measured idle/active/soak resources, rollback and firmware test evidence, and any
remaining blockers. Never publish credentials or assert "no bugs" from one
successful launch.
