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

OS=unknown
if [ -f /etc/arch-release ]; then OS=arch
elif [ -f /etc/void-release ] || [ -d /etc/xbps.d ]; then OS=void
elif [ -f /etc/debian_version ]; then OS=debian
fi

runtime_deps() {
    [ "$DEPS" = 1 ] || return 0
    say 'Checking NIRUSEC GUI runtime dependencies…'
    case "$OS" in
        debian)
            sudo apt-get install -y libxkbcommon-x11-0 libx11-6 libgl1 libegl1 libxcb1 libxkbcommon0 ufw >/dev/null 2>&1 || say 'warning: could not verify all GUI runtime packages'
            ;;
        arch)
            sudo pacman -S --needed --noconfirm libxkbcommon libxkbcommon-x11 libx11 libxcb libglvnd ufw >/dev/null 2>&1 || say 'warning: could not verify all GUI runtime packages'
            ;;
        void)
            sudo xbps-install -y libxkbcommon libxkbcommon-x11 libX11 libxcb libglvnd ufw >/dev/null 2>&1 || say 'warning: could not verify all GUI runtime packages'
            ;;
        *) say 'warning: unknown distribution; check libxkbcommon-x11 and OpenGL manually' ;;
    esac
}

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
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
    URL="https://github.com/nirucon/nirusec/releases/download/v${NIRUSEC_VERSION:-$VERSION}/nirusec"
    say "Downloading prebuilt NIRUSEC ${NIRUSEC_VERSION:-$VERSION}…"
    if need curl; then
        curl -fsSL --retry 3 -o "$TMP/nirusec" "$URL" || die 'could not download the prebuilt binary; no local build is attempted'
    else
        wget -qO "$TMP/nirusec" "$URL" || die 'could not download the prebuilt binary; no local build is attempted'
    fi
    BIN_SRC="$TMP/nirusec"
fi

chmod +x "$BIN_SRC" 2>/dev/null || true
[ -x "$BIN_SRC" ] || die 'NIRUSEC binary not found'

runtime_deps
install -d -m 0755 "$BINDIR" "$APPDIR" "$ICONDIR"
install -m 0755 "$BIN_SRC" "$BINDIR/nirusec"
install -m 0644 assets/nirusec.svg "$ICONDIR/nirusec.svg"
sed "s|^Exec=nirusec$|Exec=$BINDIR/nirusec|" assets/nirusec.desktop > "$APPDIR/nirusec.desktop"
chmod 0644 "$APPDIR/nirusec.desktop"

say 'Installing the single binary as the fixed privileged helper and PolicyKit action…'
sudo install -D -m 0755 "$BIN_SRC" "$HELPER"
sudo install -D -m 0644 assets/se.nirucon.nirusec.policy "$POLICY"

if need update-desktop-database; then update-desktop-database "$APPDIR" >/dev/null 2>&1 || :; fi
if need gtk-update-icon-cache; then gtk-update-icon-cache -q "$(dirname "$(dirname "$ICONDIR")")" >/dev/null 2>&1 || :; fi

say 'Writing the initial status cache…'
"$BINDIR/nirusec" --check --quiet || say 'warning: initial status check failed; open NIRUSEC to retry'

say "Installed NIRUSEC at $BINDIR/nirusec"
say "Privileged helper: $HELPER"
say 'Run: nirusec'
say 'The firewall is never enabled automatically by installation.'
