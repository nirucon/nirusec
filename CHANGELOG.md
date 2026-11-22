# Changelog

## 0.3.0 (2026-11-22)

- The window is drawn with x11rb and a small software canvas (the NIRUFM
  toolkit) instead of egui and OpenGL: first frame in about 15 ms instead of
  about 100 ms, 8 MB of memory instead of about 115 MB, no CPU while idle.
- The release binary is static (musl); no OpenGL, xkbcommon or other GUI
  libraries are needed. The installer only provisions UFW and PolicyKit.
- Every view, confirmation, PolicyKit flow and narrow layout is kept. New
  keys: Tab/Shift+Tab focus, Enter/Space press, Ctrl+1 to Ctrl+7 views,
  F5 or Ctrl+R refresh, Page Up/Down and Home/End scroll, Ctrl+V paste,
  Ctrl+Q close. The command output of a privileged action has a Copy button.
- The theme follows `_NIRUWM_THEME` on the root window and reloads through
  inotify instead of polling the configuration every 2 seconds.
- `tests/xvfb.sh`: end-to-end test (first frame, memory, idle CPU, profile
  change with Keep, rule editor, confirmation dialog) with the fixture helper.
