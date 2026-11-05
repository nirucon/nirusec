#!/bin/bash
# Run the NIRUSEC firewall integration tests in an isolated network and mount
# namespace. Requires root (sudo) and UFW, iproute2 and python3 on the host.
# The host firewall, /etc, /run and /var are never modified.
#
#   sudo tests/netns/run.sh target/release/nirusec
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=$(readlink -f "${1:-target/release/nirusec}")
[ -x "$bin" ] || { echo "usage: $0 path/to/nirusec" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (inside a private namespace)" >&2; exit 2; }
NIRUSEC_HOST_NETNS=$(readlink /proc/self/ns/net)
export NIRUSEC_HOST_NETNS
exec unshare --net --mount --propagation private -- \
    bash -c 'source "$0/lib.sh"; ns_setup "$1"; source "$0/firewall.sh"' "$here" "$bin"
