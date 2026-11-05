#!/bin/sh
# Remove the NIRUSEC GUI, root helper and PolicyKit action.
# Firewall rules, NIRUSEC state (/var/lib/nirusec), backups
# (/var/backups/nirusec) and local exceptions (/etc/nirusec) are kept.
set -eu
PREFIX="${NIRUSEC_PREFIX:-$HOME/.local}"
if grep -q '"state": *"pending"' /var/lib/nirusec/state.json 2>/dev/null; then
    printf '%s\n' 'nirusec uninstall: a firewall change is waiting for Keep/Undo; resolve it in NIRUSEC first (its automatic undo needs the helper).' >&2
    exit 1
fi
sudo rm -f /usr/local/libexec/nirusec-helper /usr/share/polkit-1/actions/se.nirucon.nirusec.policy 2>/dev/null || true
rm -f "$PREFIX/bin/nirusec" "$PREFIX/share/applications/nirusec.desktop" "$PREFIX/share/icons/hicolor/scalable/apps/nirusec.svg"
printf 'Removed NIRUSEC. Firewall rules, preferences, cache and backups were kept.\n'
