#!/bin/sh
# NIRUSEC installer.
#
#   ./install.sh             install from target/release (build if needed)
#   ./install.sh --build     build both binaries from this checkout
#   ./install.sh --prebuilt  use ./nirusec and ./nirusec-helper beside this script
#   ./install.sh --no-deps   do not provision GUI runtime packages
#
# The user GUI is installed without root. Only the fixed root helper and its
# PolicyKit action use sudo.
set -eu

PREFIX="${NIRUSEC_PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"
APPDIR="$PREFIX/share/applications"
ICONDIR="$PREFIX/share/icons/hicolor/scalable/apps"
HELPER=/usr/local/libexec/nirusec-helper
POLICY=/usr/share/polkit-1/actions/se.nirucon.nirusec.policy
MODE=auto
DEPS=1

for arg in "$@"; do
    case "$arg" in
        --build) MODE=build ;;
        --prebuilt) MODE=prebuilt ;;
        --no-deps) DEPS=0 ;;
        --help)
            printf '%s\n' "Usage: ./install.sh [--build|--prebuilt] [--no-deps]"
            exit 0
            ;;
        *) printf 'nirusec install: unknown option %s\n' "$arg" >&2; exit 2 ;;
    esac
done

say() { printf '%s\n' "$*"; }
die() { say "nirusec install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" = 0 ]; then
    die 'run ./install.sh as your desktop user; the script uses sudo only for the root helper'
fi

OS=unknown
if [ -f /etc/arch-release ]; then OS=arch
elif [ -f /etc/void-release ] || [ -d /etc/xbps.d ]; then OS=void
elif [ -f /etc/debian_version ]; then OS=debian
fi

runtime_deps() {
    [ "$DEPS" = 1 ] || return 0
    say 'Installing NIRUSEC GUI runtime dependencies…'
    case "$OS" in
        debian)
            sudo apt-get install -y libxkbcommon-x11-0 libx11-6 libgl1 libegl1 libxcb1 libxkbcommon0 ufw pkexec >/dev/null 2>&1 || die 'could not install Debian runtime dependencies'
            ;;
        arch)
            sudo pacman -S --needed --noconfirm libxkbcommon libxkbcommon-x11 libx11 libxcb libglvnd ufw polkit >/dev/null 2>&1 || die 'could not install Arch runtime dependencies'
            ;;
        void)
            sudo xbps-install -y libxkbcommon libxkbcommon-x11 libX11 libxcb libglvnd ufw polkit >/dev/null 2>&1 || die 'could not install Void runtime dependencies'
            ;;
        *) say 'warning: unknown distribution; check libxkbcommon-x11, OpenGL, UFW and pkexec manually' ;;
    esac
}

VERSION="${NIRUSEC_VERSION:-}"
if [ -z "$VERSION" ] && [ -f Cargo.toml ]; then
    VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
fi
if [ -z "$VERSION" ] && [ -f VERSION ]; then
    VERSION="$(sed -n '1p' VERSION)"
fi
[ -n "$VERSION" ] || die 'cannot determine NIRUSEC version (set NIRUSEC_VERSION)'
ARCH="$(uname -m)"
[ "$ARCH" = "x86_64" ] || die "no prebuilt release for $ARCH; use source development with --build"

TMP=""
trap 'rm -rf "$TMP"' EXIT
if [ "$MODE" = build ]; then
    need cargo || die 'Rust/cargo is required for --build'
    say 'Building NIRUSEC for local development…'
    cargo build --release --locked
    BIN_SRC=target/release/nirusec
elif [ -x ./nirusec ]; then
    BIN_SRC=./nirusec
elif [ -x target/release/nirusec ]; then
    BIN_SRC=target/release/nirusec
else
    need curl || need wget || die 'curl or wget is required to download the prebuilt binary'
    TMP=$(mktemp -d)
    URL="https://github.com/nirucon/nirusec/releases/download/v${VERSION}/nirusec"
    SUMS_URL="https://github.com/nirucon/nirusec/releases/download/v${VERSION}/SHA256SUMS"
    say "Downloading prebuilt NIRUSEC ${VERSION}…"
    if need curl; then
        curl -fsSL --retry 3 -o "$TMP/nirusec" "$URL" || die 'could not download the prebuilt binary; no local build is attempted'
        curl -fsSL --retry 3 -o "$TMP/SHA256SUMS" "$SUMS_URL" || die 'could not download release checksums'
    else
        wget -qO "$TMP/nirusec" "$URL" || die 'could not download the prebuilt binary; no local build is attempted'
        wget -qO "$TMP/SHA256SUMS" "$SUMS_URL" || die 'could not download release checksums'
    fi
    need sha256sum || die 'sha256sum is required to verify the release binary'
    expected=$(awk '$2 == "nirusec" || $2 == "*nirusec" { print $1; exit }' "$TMP/SHA256SUMS")
    [ -n "$expected" ] || die 'release checksum file does not contain nirusec'
    actual=$(sha256sum "$TMP/nirusec" | awk '{print $1}')
    [ "$expected" = "$actual" ] || die 'downloaded NIRUSEC binary failed SHA-256 verification'
    say 'SHA-256 verification passed.'
    BIN_SRC="$TMP/nirusec"
fi

chmod +x "$BIN_SRC" 2>/dev/null || true
[ -x "$BIN_SRC" ] || die 'NIRUSEC binary not found'
if [ -f SHA256SUMS ] && [ "$MODE" != build ]; then
    need sha256sum || die 'sha256sum is required to verify the release binary'
    expected=$(awk '$2 == "nirusec" || $2 == "*nirusec" { print $1; exit }' SHA256SUMS)
    actual=$(sha256sum "$BIN_SRC" | awk '{print $1}')
    [ -n "$expected" ] && [ "$expected" = "$actual" ] \
        || die 'local NIRUSEC binary failed SHA-256 verification'
    say 'SHA-256 verification passed.'
fi

runtime_deps
install -d -m 0755 "$BINDIR" "$APPDIR" "$ICONDIR"
install -m 0755 "$BIN_SRC" "$BINDIR/nirusec"
install -m 0644 assets/nirusec.svg "$ICONDIR/nirusec.svg"
sed "s|^Exec=nirusec$|Exec=$BINDIR/nirusec|" assets/nirusec.desktop > "$APPDIR/nirusec.desktop"
chmod 0644 "$APPDIR/nirusec.desktop"

say 'Installing the single binary as the fixed privileged helper and PolicyKit action…'
sudo install -D -m 0755 "$BIN_SRC" "$HELPER"
sudo install -D -m 0644 assets/se.nirucon.nirusec.policy "$POLICY"
need pkexec || die 'pkexec (PolicyKit) is required for privileged firewall and update actions'
if need pkaction; then
    pkaction --action-id se.nirucon.nirusec.status >/dev/null 2>&1 \
        || say 'warning: PolicyKit has not loaded se.nirucon.nirusec.status yet; verify after the next login if authentication fails'
fi

if need update-desktop-database; then update-desktop-database "$APPDIR" >/dev/null 2>&1 || :; fi
if need gtk-update-icon-cache; then gtk-update-icon-cache -q "$(dirname "$(dirname "$ICONDIR")")" >/dev/null 2>&1 || :; fi

say 'Writing the initial status cache…'
"$BINDIR/nirusec" --check --quiet || say 'warning: initial status check failed; open NIRUSEC to retry'

say "Installed NIRUSEC at $BINDIR/nirusec"
say "Privileged helper: $HELPER"
say 'Run: nirusec'
say 'The firewall is never enabled automatically by installation.'
