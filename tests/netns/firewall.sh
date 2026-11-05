# shellcheck shell=bash
# Firewall scenarios. Sourced by run.sh inside the private namespace after
# ns_setup. Uses $HELPER (the binary under test at the fixed helper path).
set +e
set -uo pipefail

H=$HELPER
mkdir -p /etc/nirusec
printf 'rollback_seconds = 20\n' > /etc/nirusec/settings.toml
chmod 0644 /etc/nirusec/settings.toml

json() { python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {"d": d}))' "$1"; }
helper() { "$H" "$@" 2>/dev/null; }
token_of() { printf '%s' "$1" | json 'd.get("token") or ""'; }
ok_of() { printf '%s' "$1" | json 'd["ok"]'; }
state() { python3 -I -c 'import json; print(json.load(open("/var/lib/nirusec/state.json"))["state"])' 2>/dev/null; }
label() { python3 -I -c 'import json; print(json.load(open("/var/lib/nirusec/state.json"))["label"])' 2>/dev/null; }
added() { ufw show added 2>/dev/null | sed -n 's/^ufw //p'; }
probe_loop() { # probe_loop SECONDS PORT -> writes /tmp/probe.txt in background
    ( end=$((SECONDS + $1)); while [ $SECONDS -lt $end ]; do reach lan 192.168.77.1 "$2"; reach lan fd77::1 "$2"; sleep 0.05; done ) > /tmp/probe.txt &
    PROBE=$!
}

echo "# --- T0 isolation guard"
check "running in a private netns" yes "$([ "$(readlink /proc/self/ns/net)" != "$NIRUSEC_HOST_NETNS" ] && echo yes)"

echo "# --- T1 Soft profile from an enabled firewall, no open window"
ufw allow 22/tcp >/dev/null; ufw --force enable >/dev/null
echo "# custom before.rules marker" >> /etc/ufw/before.rules
check "8080 blocked before" blocked "$(reach lan 192.168.77.1 8080)"
probe_loop 12 8080
sleep 0.3
t0=$(date +%s%N)
out=$(helper profile-apply soft); t1=$(date +%s%N)
wait $PROBE
echo "#   apply took $(( (t1 - t0) / 1000000 )) ms"
check "soft apply ok" True "$(ok_of "$out")"
TOKEN=$(token_of "$out")
check "token returned" 32 "${#TOKEN}"
check "never-allowed port stayed blocked during apply" 0 "$(grep -c open /tmp/probe.txt)"
check "custom before.rules kept" 1 "$(grep -c 'custom before.rules marker' /etc/ufw/before.rules)"
check "no ufw reset backup files" 0 "$(ls /etc/ufw | grep -c 'rules\.20')"
check "state pending" pending "$(state)"
check "public state has no token" 0 "$(grep -c "$TOKEN" /var/lib/nirusec/state.json)"
check "state.json mode" 644 "$(stat -c %a /var/lib/nirusec/state.json)"
check "tx record mode" 600 "$(stat -c %a /var/lib/nirusec/tx/"$TOKEN".json)"
check "lan ssh v4 open" open "$(reach lan 192.168.77.1 22)"
check "lan ssh v6 open (IPv6 parity)" open "$(reach lan fd77::1 22)"
check "internet ssh blocked" blocked "$(reach wan 203.0.113.1 22)"
check "internet ssh v6 blocked" blocked "$(reach wan 2001:db8:77::1 22)"
check "tailscale 8080 open" open "$(reach ts 100.100.1.1 8080)"
check "lan 8080 blocked" blocked "$(reach lan 192.168.77.1 8080)"
exp=$("$CLI" --profile-rules soft | sed -n 's/^ufw //p')
check "show added == preview" "$exp" "$(added)"
out=$(helper rules-add '[{"action":"allow","protocol":"tcp","port":"9000","source":"any"}]')
check "manual change refused while pending" False "$(ok_of "$out")"
out=$(helper tx-confirm "$TOKEN")
check "keep ok" True "$(ok_of "$out")"
sleep 0.3
check "watchdog ended on keep" 0 "$(pgrep -fc "tx-watchdog $TOKEN" || true)"
check "state kept" kept "$(state)"
check "label Soft" Soft "$(label)"
out=$(helper ufw-status)
check "verified after keep" "[]" "$(printf '%s' "$out" | json 'd["data"]["drift"]')"
check "status running" True "$(printf '%s' "$out" | json 'd["data"]["running"]')"
out=$(helper tx-confirm "$TOKEN")
check "token cannot be reused" False "$(ok_of "$out")"

echo "# --- T2 external edit is detected"
ufw allow 9999/tcp >/dev/null
out=$(helper ufw-status)
check_grep "drift lists user.rules" "user.rules" "$(printf '%s' "$out" | json 'd["data"]["drift"]')"
ufw --force delete allow 9999/tcp >/dev/null 2>&1 || ufw delete allow 9999/tcp >/dev/null
out=$(helper ufw-status)

echo "# --- T3 switch Soft -> Hard, not kept: automatic rollback after the window"
probe_loop 4 22
out=$(helper profile-apply hard)
wait $PROBE
check "hard apply ok" True "$(ok_of "$out")"
check "lan ssh blocked under hard" blocked "$(reach lan 192.168.77.1 22)"
check "tailscale ssh open under hard" open "$(reach ts 100.100.1.1 22)"
check "hard has no 41641" 0 "$(added | grep -c 41641)"
out=$(helper profile-apply medium)
check "second apply refused while pending" False "$(ok_of "$out")"
echo "#   waiting for the rollback window (20 s)"
sleep 24
check "state after expiry" kept "$(state)"
check "label back to Soft" Soft "$(label)"
check "lan ssh open again after rollback" open "$(reach lan 192.168.77.1 22)"
check "rules back to Soft" "$exp" "$(added)"
check "no watchdog left" 0 "$(pgrep -fc 'tx-watchdog' || true)"

echo "# --- T4 undo now"
out=$(helper profile-apply medium); TOKEN=$(token_of "$out")
check "medium pending" pending "$(state)"
out=$(helper tx-undo "$TOKEN")
check "undo ok" True "$(ok_of "$out")"
check "undo back to Soft" "$exp" "$(added)"
check "label after undo" Soft "$(label)"

echo "# --- T5 interrupted by a reboot"
out=$(helper profile-apply medium); TOKEN=$(token_of "$out")
pkill -f "tx-watchdog $TOKEN" || true
echo "00000000-0000-0000-0000-000000000000" > /tmp/fake_boot_id
mount --bind /tmp/fake_boot_id /proc/sys/kernel/random/boot_id
check "profile state interrupted" interrupted "$("$CLI" --profile-state | json 'd["state"]')"
out=$(helper ufw-status)
check "status reports interrupted" True "$(printf '%s' "$out" | json 'd["data"]["unresolved"][0]["interrupted"]')"
out=$(helper profile-apply hard)
check "new apply refused while interrupted" False "$(ok_of "$out")"
out=$(helper tx-resolve restore)
check "resolve restore ok" True "$(ok_of "$out")"
check "rules back to Soft after resolve" "$exp" "$(added)"
umount /proc/sys/kernel/random/boot_id

echo "# --- T6 delete removes the IPv4 and IPv6 halves together"
out=$(helper rules-add '[{"action":"allow","protocol":"tcp","port":"8080","source":"any","comment":"web test"}]')
check "add 8080 ok" True "$(ok_of "$out")"
check "allow add needs no window" "" "$(token_of "$out")"
check "lan 8080 v6 open" open "$(reach lan fd77::1 8080)"
num=$(ufw status numbered | grep '8080/tcp ' | grep -v v6 | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p')
twin=$(ufw status numbered | grep '8080/tcp (v6)' | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p')
raw() { ufw status numbered | sed -n "s/^\[ *$1\] //p" | sed 's/[[:space:]]*$//'; }
out=$(helper rule-delete "$num" "stale text")
check "stale delete refused" False "$(ok_of "$out")"
out=$(helper rule-delete "$num")
check "delete without expected text refused" False "$(ok_of "$out")"
out=$(helper rule-delete "$num" "$(raw "$num")" "$twin" "$(raw "$twin")")
check "delete ok" True "$(ok_of "$out")"
TOKEN=$(token_of "$out")
helper tx-confirm "$TOKEN" >/dev/null
check "8080 v4 rule gone" blocked "$(reach lan 192.168.77.1 8080)"
check "8080 v6 twin gone" blocked "$(reach lan fd77::1 8080)"
check "no 8080 left" 0 "$(ufw status | grep -c 8080)"

echo "# --- T7 block rule goes first, has a rollback window, undo works"
out=$(helper rules-add '[{"action":"deny","protocol":"tcp","port":"22","source":"any"}]')
TOKEN=$(token_of "$out")
check "block rule armed a window" 32 "${#TOKEN}"
check "block rule is first" 1 "$(ufw status numbered | grep '^\[ 1\]' | grep -c DENY)"
check "lan ssh blocked by deny" blocked "$(reach lan 192.168.77.1 22)"
check "tailscale ssh blocked by deny" blocked "$(reach ts 100.100.1.1 22)"
helper tx-undo "$TOKEN" >/dev/null
check "lan ssh back after undo" open "$(reach lan 192.168.77.1 22)"
check "rules back to Soft after undo" "$exp" "$(added)"

echo "# --- T8 safe mode always works, even with a pending change"
out=$(helper profile-apply hard); TOKEN=$(token_of "$out")
out=$(helper safe-mode)
check "safe mode ok while pending" True "$(ok_of "$out")"
check "internet ssh open in safe mode" open "$(reach wan 203.0.113.1 22)"
check "pending change superseded" 0 "$(python3 -I -c 'import json,glob; print(sum(json.load(open(f))["state"]=="pending" for f in glob.glob("/var/lib/nirusec/tx/*.json")))')"
sleep 22
check "superseded watchdog did not undo safe mode" open "$(reach wan 203.0.113.1 22)"

echo "# --- T9 input validation at the helper boundary"
for bad in '[{"action":"allow","protocol":"tcp","port":"22;id","source":"any"}]' \
           '[{"action":"allow","protocol":"tcp","port":"22","source":"any","shell":"x"}]' \
           '[{"action":"allow","protocol":"any","port":"any","source":"any"}]' \
           '[{"action":"allow","protocol":"tcp","port":"22","source":"any","comment":"it'"'"'s"}]' \
           '[{"action":"allow","protocol":"tcp","port":"22","source":"any","interface":"-x"}]' \
           '[]' 'not json'; do
    out=$(helper rules-add "$bad")
    check "rejects $(printf '%.40s' "$bad")" False "$(ok_of "$out")"
done
out=$(helper ufw-status extra)
check "extra argument rejected" False "$(ok_of "$out")"
out=$(helper no-such-op)
check "unknown op rejected" False "$(ok_of "$out")"
out=$(helper firmware-update)
check "firmware update needs a device" False "$(ok_of "$out")"
out=$(helper backup-restore "../../etc")
check "backup path traversal rejected" False "$(ok_of "$out")"
out=$(helper tx-undo "../../etc/passwd")
check "token traversal rejected" False "$(ok_of "$out")"

echo "# --- T10 local exceptions survive profile switches"
out=$(helper profile-apply soft); helper tx-confirm "$(token_of "$out")" >/dev/null
out=$(helper rules-add '[{"action":"allow","protocol":"tcp","port":"8080","source":"192.168.77.0/24","comment":"lab"}]' --keep)
check "add exception ok" True "$(ok_of "$out")"
check "exceptions file mode" 600 "$(stat -c %a /etc/nirusec/local-exceptions.toml)"
check "still Soft with exception" Soft "$(label)"
out=$(helper profile-apply medium); helper tx-confirm "$(token_of "$out")" >/dev/null
check "lan 8080 open via exception under Medium" open "$(reach lan 192.168.77.1 8080)"
check "lan ssh blocked under Medium" blocked "$(reach lan 192.168.77.1 22)"
check "Medium preview includes exception" "$("$CLI" --profile-rules medium | sed -n 's/^ufw //p')" "$(added)"
out=$(helper ufw-status)
check "status lists the exception" 1 "$(printf '%s' "$out" | json 'len(d["data"]["exceptions"])')"
out=$(helper exception-remove '{"action":"allow","protocol":"tcp","port":"8080","source":"192.168.77.0/24","comment":"lab"}')
check "remove exception ok" True "$(ok_of "$out")"
out=$(helper profile-apply medium); helper tx-confirm "$(token_of "$out")" >/dev/null
check "8080 closed after exception removal + reapply" blocked "$(reach lan 192.168.77.1 8080)"

echo "# --- T11 fast reload yields the same netfilter state as ufw reload"
norm() { { iptables-save; ip6tables-save; } | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//' ; }
out=$(helper profile-apply soft); helper tx-confirm "$(token_of "$out")" >/dev/null
fast=$(norm)
ufw reload >/dev/null
check "fast reload == ufw reload" "$(norm)" "$fast"

echo "# --- T12 Off profile and turning the firewall back on"
out=$(helper profile-apply off); helper tx-confirm "$(token_of "$out")" >/dev/null
check "off: ufw inactive" "Status: inactive" "$(ufw status | head -1)"
check "off: label" Off "$(label)"
check "off: 8080 reachable" open "$(reach lan 192.168.77.1 8080)"
out=$(helper ufw-enable)
TOKEN=$(token_of "$out")
check "enable arms a window" 32 "${#TOKEN}"
helper tx-confirm "$TOKEN" >/dev/null
check "enabled again" "Status: active" "$(ufw status | head -1)"

echo "# --- T13 restore a historical backup (windowed)"
b=$(ls /var/backups/nirusec | head -1)
out=$(helper backup-restore "$b")
TOKEN=$(token_of "$out")
check "backup restore ok" True "$(ok_of "$out")"
check "backup restore windowed" 32 "${#TOKEN}"
helper tx-undo "$TOKEN" >/dev/null
check "history is root-only" 600 "$(stat -c %a /var/lib/nirusec/history.jsonl)"
check "history bounded" yes "$([ "$(wc -l < /var/lib/nirusec/history.jsonl)" -le 200 ] && echo yes)"

echo "# --- T14 upgrade from a 0.1.8 pending state"
rm -f /var/lib/nirusec/state.json
mkdir -p /run/nirusec
printf '{"schema":1,"id":"soft","label":"Soft","state":"pending","applied_at":1,"expires_at":2,"pending_token":"1-2"}' > /run/nirusec/profile.json
rm -f /run/nirusec/firewall.lock
check "legacy pending shown as interrupted" interrupted "$("$CLI" --profile-state | json 'd["state"]')"
out=$(helper profile-apply soft)
check "legacy pending blocks apply" False "$(ok_of "$out")"
out=$(helper tx-resolve keep)
check "legacy resolve keep" True "$(ok_of "$out")"
check "legacy state retired" no "$([ -e /run/nirusec/profile.json ] && echo yes || echo no)"

ns_finish
