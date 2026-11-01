#!/bin/sh
set -eu
PREFIX="${NIRUSEC_PREFIX:-$HOME/.local}"
sudo rm -f /usr/local/libexec/nirusec-helper /usr/share/polkit-1/actions/se.nirucon.nirusec.policy 2>/dev/null || true
rm -f "$PREFIX/bin/nirusec" "$PREFIX/share/applications/nirusec.desktop" "$PREFIX/share/icons/hicolor/scalable/apps/nirusec.svg"
printf 'Removed NIRUSEC. Preferences and cache were kept.\n'
