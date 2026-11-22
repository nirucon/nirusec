#!/bin/sh
# X11 end-to-end checks of the GUI in a private Xvfb with the test-only
# fixture helper (no root, no PolicyKit): first frame, memory, idle CPU,
# view switching, a profile change with Keep, the rule editor with a
# drop-down and text input, and the confirmation dialog.
#   tests/xvfb.sh PATH/TO/nirusec [DISPLAY_NUMBER]
set -eu
BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
SB=$(mktemp -d)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$SB"; }
trap cleanup EXIT INT TERM
export HOME=$SB/home XDG_CONFIG_HOME=$SB/config XDG_STATE_HOME=$SB/state XDG_CACHE_HOME=$SB/cache
export NIRUSEC_HELPER=$HERE/gui/fixture-helper NIRUSEC_TEST_STATE_DIR=$SB/tx NIRU_UI_TRACE=1
mkdir -p "$HOME" "$XDG_CONFIG_HOME/niruwm" "$SB/tx"
echo 'theme = "niru-nord"' > "$XDG_CONFIG_HOME/niruwm/config.toml"
D=:${2:-$((70 + $$ % 20))}
Xvfb "$D" -screen 0 1280x900x24 -nolisten tcp >/dev/null 2>&1 &
PIDS="$PIDS $!"
export DISPLAY=$D
sleep 1
fail() { echo "FAIL: $*" >&2; tail -5 "$SB/err" >&2; exit 1; }
# Centre of control NAME in the last drawn frame: "x y".
at() {
    awk -v n="$1" -F'|' '/^ui-frame/ {p = ""} $1 == "ui" && $2 == n {p = $3 " " $4} END {print p}' "$SB/err"
}
# Click NAME, scrolling the page down (mouse wheel) until it is on screen.
click() {
    n=0
    while [ -z "$(at "$1")" ]; do
        n=$((n + 1)); [ $n -lt 40 ] || fail "no control '$1'"
        [ $n -gt 3 ] && xdotool mousemove 640 600 click 5
        sleep 0.15
    done
    set -- $(at "$1"); xdotool mousemove "$1" "$2" click 1; sleep 0.5
}
ops() { cat "$SB/tx/ops.log" 2>/dev/null || true; }

NIRUSEC_TIMING=1 "$BIN" --open firewall 2>"$SB/err" &
A=$!
PIDS="$PIDS $A"
sleep 1.5
W=$(xdotool search --pid "$A" | head -1)
xdotool windowmove "$W" 0 0 windowsize "$W" 1100 860; sleep 0.8
grep -q 'first frame after' "$SB/err" || fail "no first frame"
ms=$(sed -n 's/.*first frame after \([0-9]*\)\..*/\1/p' "$SB/err" | head -1)
[ "$ms" -lt 1000 ] || fail "first frame took $ms ms"
rss=$(awk '/VmRSS/ {print $2}' /proc/$A/status)
[ "$rss" -lt 60000 ] || fail "memory $rss kB"
a=$(awk '{print $14+$15}' /proc/$A/stat); sleep 3; b=$(awk '{print $14+$15}' /proc/$A/stat)
[ $((b - a)) -le 1 ] || fail "busy while idle: $((b - a)) ticks in 3 s"
echo "first frame ${ms} ms, ${rss} kB, idle $((b - a)) ticks/3 s"

# The status check through the helper ran and the rules are listed.
ops | grep -q '^ufw-status' || fail "no ufw-status"
xdotool key End; sleep 0.6
[ -n "$(at 'Remove…')" ] || fail "rules not listed"
[ -n "$(at 'Restore before this…')" ] || fail "history not listed"
xdotool key Home; sleep 0.6
echo "firewall status ok"

# Profile: preview, try it, keep it.
click 'Preview Medium…'
click 'Try it for 120 s'
ops | grep -q '^profile-apply medium' || fail "profile-apply not run: $(ops)"
sleep 1
click 'Keep'
ops | grep -q '^tx-confirm 0000' || fail "Keep did not confirm: $(ops)"
echo "profile change ok"

# Rule editor: pick "A specific port…" from the drop-down with the keyboard,
# type a port and a note, and apply.
click 'nirusec-preset'
for k in Down Down Down Down Down Down Down Return; do xdotool key $k; sleep 0.1; done
sleep 0.4
click 'nirusec-port'
xdotool type --delay 30 '8080'
click 'nirusec-note'
xdotool type --delay 30 'printer'
sleep 0.3
click 'Allow…'
click 'Cancel'
ops | grep -q '^rules-add' && fail "Cancel applied the rule"
click 'Allow…'
click 'Apply'
ops | grep -q '^rules-add .*8080.*printer' || fail "rule not added: $(ops)"
echo "rule editor ok"

# Esc closes a confirmation; Ctrl+3 switches to Ports.
click 'Emergency safe mode…'
[ -n "$(at 'Cancel')" ] || fail "no dialog"
xdotool key Escape; sleep 0.5
xdotool key ctrl+3; sleep 0.5
xdotool key ctrl+1; sleep 0.5
ops | grep -q '^safe-mode' && fail "Esc ran safe mode"
echo "keys ok"
echo PASS
