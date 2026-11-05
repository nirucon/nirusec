# shellcheck shell=bash
# Shared setup for NIRUSEC firewall tests in an isolated network + mount
# namespace. Sourced by run.sh *inside* `unshare --net --mount`.
#
# Nothing here may reach the host firewall or host configuration:
#   * the network namespace has its own netfilter tables;
#   * /etc is an overlay whose upper layer lives on a private tmpfs;
#   * /run, /var/lib, /var/backups and /tmp are private tmpfs mounts;
#   * systemd-run is masked so no watchdog can escape into the host manager.
set -euo pipefail

ns_guard() {
    # Refuse to run in the host network namespace.
    if [ "$(readlink /proc/self/ns/net)" = "${NIRUSEC_HOST_NETNS:-}" ] || [ -z "${NIRUSEC_HOST_NETNS:-}" ]; then
        echo "netns guard: not inside a private network namespace" >&2
        exit 99
    fi
    if [ "$(id -u)" != 0 ]; then
        echo "netns guard: must run as root inside the namespace" >&2
        exit 99
    fi
}

ns_setup() {
    local bin=$1
    ns_guard
    mount --make-rprivate /
    mount -t tmpfs -o mode=1777 tmpfs /tmp
    mkdir -p /tmp/ov/upper /tmp/ov/work
    mount -t overlay overlay -o lowerdir=/etc,upperdir=/tmp/ov/upper,workdir=/tmp/ov/work /etc
    mount -t tmpfs -o mode=0755 tmpfs /run
    mount -t tmpfs -o mode=0755 tmpfs /var/lib
    mkdir -p /var/backups
    mount -t tmpfs -o mode=0755 tmpfs /var/backups
    mkdir -p /usr/local/libexec 2>/dev/null || true
    mount -t tmpfs -o mode=0755 tmpfs /usr/local/libexec
    install -m 0755 "$bin" /usr/local/libexec/nirusec-helper
    HELPER=/usr/local/libexec/nirusec-helper
    mkdir -p /tmp/cli && install -m 0755 "$bin" /tmp/cli/nirusec
    CLI=/tmp/cli/nirusec
    local sr
    for sr in /usr/bin/systemd-run /bin/systemd-run; do
        if [ -e "$sr" ] && [ ! -L "$sr" ]; then mount --bind /dev/null "$sr"; fi
    done
    # Deterministic UFW starting point: package templates, IPv6 on, inactive.
    local share=/usr/share/ufw/iptables
    cp "$share"/*.rules /etc/ufw/
    rm -f /etc/ufw/*.rules.20*   # old `ufw reset` copies (overlay only)
    sed -i 's/^ENABLED=.*/ENABLED=no/' /etc/ufw/ufw.conf
    sed -i -e 's/^IPV6=.*/IPV6=yes/' \
        -e 's/^DEFAULT_INPUT_POLICY=.*/DEFAULT_INPUT_POLICY="DROP"/' \
        -e 's/^DEFAULT_OUTPUT_POLICY=.*/DEFAULT_OUTPUT_POLICY="ACCEPT"/' /etc/default/ufw
    rm -rf /etc/nirusec
    ip link set lo up
    sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0 >/dev/null 2>&1 || true
    mkdir -p /run/netns
    peer lan lan0 192.168.77 fd77
    peer wan wan0 203.0.113 2001:db8:77
    peer ts tailscale0 100.100.1 fd7a:115c:a1e0
    listen 22
    listen 8080
}

# peer NAME IFACE V4PREFIX V6PREFIX: veth pair to a peer namespace.
peer() {
    local name=$1 dev=$2 v4=$3 v6=$4
    ip netns add "$name"
    ip link add "$dev" type veth peer name p-"$name"
    ip link set p-"$name" netns "$name"
    ip addr add "$v4.1/24" dev "$dev"
    ip addr add "$v6::1/64" dev "$dev" nodad
    ip link set "$dev" up
    ip netns exec "$name" ip link set lo up
    ip netns exec "$name" ip addr add "$v4.2/24" dev p-"$name"
    ip netns exec "$name" ip addr add "$v6::2/64" dev p-"$name" nodad
    ip netns exec "$name" ip link set p-"$name" up
}

listen() {
    python3 -I -c '
import socket, sys, threading
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", int(sys.argv[1])))
s.listen(16)
while True:
    c, _ = s.accept()
    c.close()
' "$1" >/dev/null 2>&1 &
    LISTENERS="${LISTENERS:-} $!"
    sleep 0.2
}

# reach PEER ADDR PORT -> prints open|blocked
reach() {
    if ip netns exec "$1" timeout 2 python3 -I -c '
import socket, sys
a, p = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in a else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.settimeout(1.5)
s.connect((a, p))
' "$2" "$3" >/dev/null 2>&1; then echo open; else echo blocked; fi
}

PASS=0
FAIL=0
check() { # check NAME EXPECTED ACTUAL
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1)); echo "ok   - $1"
    else
        FAIL=$((FAIL + 1)); echo "FAIL - $1 (expected '$2', got '$3')"
    fi
}
check_grep() { # check_grep NAME PATTERN TEXT
    if printf '%s' "$3" | grep -qE -- "$2"; then
        PASS=$((PASS + 1)); echo "ok   - $1"
    else
        FAIL=$((FAIL + 1)); echo "FAIL - $1 (no match for '$2')"; printf '%s\n' "$3" | sed 's/^/       | /' | head -20
    fi
}
check_nogrep() {
    if printf '%s' "$3" | grep -qE -- "$2"; then
        FAIL=$((FAIL + 1)); echo "FAIL - $1 (unexpected '$2')"; printf '%s\n' "$3" | sed 's/^/       | /' | head -20
    else
        PASS=$((PASS + 1)); echo "ok   - $1"
    fi
}

ns_finish() {
    local pid
    for pid in ${LISTENERS:-}; do kill "$pid" 2>/dev/null || true; done
    echo "# passed $PASS, failed $FAIL"
    [ "$FAIL" = 0 ]
}
