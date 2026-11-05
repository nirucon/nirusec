#!/bin/bash
# Screenshot NIRUSEC at several widths under Xvfb with the fixture helper.
#   tests/gui/run-xvfb.sh path/to/nirusec OUTDIR
set -euo pipefail
bin=$(readlink -f "$1"); out=$(readlink -f "$2"); here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
fifo=$(mktemp -u); mkfifo "$fifo"
Xvfb -displayfd 3 -screen 0 1600x1000x24 -nolisten tcp 3>"$fifo" >/dev/null 2>&1 &
XPID=$!
trap 'kill $XPID 2>/dev/null || true; rm -f "$fifo"' EXIT
read -r -t 10 num <"$fifo"
export DISPLAY=":$num"
state=$(mktemp -d)
export NIRUSEC_HELPER="$here/fixture-helper" NIRUSEC_TEST_STATE_DIR="$state"
export XDG_STATE_HOME="$state/xdg"
shoot() { # shoot NAME WIDTH HEIGHT [ARGS...]
    local name=$1 w=$2 h=$3; shift 3
    "$bin" "$@" & local pid=$!
    local wid=""
    for _ in $(seq 1 50); do wid=$(xdotool search --pid "$pid" 2>/dev/null | head -1 || true); [ -n "$wid" ] && break; sleep 0.2; done
    xdotool windowsize "$wid" "$w" "$h"; sleep 2.5
    import -window "$wid" "$out/$name.png"
    kill "$pid"; wait "$pid" 2>/dev/null || true
}
echo '{"schema":2,"id":"soft","label":"Soft","state":"kept","confirmed_at":'"$(date +%s)"',"exceptions":1}' > "$state/state.json"
shoot overview-1200 1200 800 --open overview
shoot firewall-1200 1200 900 --open firewall
shoot firewall-420 420 900 --open firewall
NIRUSEC_TEST_PREVIEW=medium shoot preview-medium-960 960 800 --open firewall
NIRUSEC_TEST_PREVIEW=hard shoot preview-hard-420 420 800 --open firewall
now=$(date +%s)
echo '{"schema":2,"id":"hard","label":"Hard","state":"pending","change":"switch to the Hard profile","applied_at":'"$now"',"expires_at":'"$((now + 100))"',"boot_id":"'"$(cat /proc/sys/kernel/random/boot_id)"'"}' > "$state/state.json"
NIRUSEC_TEST_TOKEN=00000000000000000000000000000000 shoot pending-960 960 700 --open firewall
echo '{"schema":2,"id":"hard","label":"Hard","state":"pending","change":"switch to the Hard profile","applied_at":1,"expires_at":2,"boot_id":"other-boot"}' > "$state/state.json"
shoot interrupted-640 640 700 --open firewall
rm -rf "$state"
ls "$out"
