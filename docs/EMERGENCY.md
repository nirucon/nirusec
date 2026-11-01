# NIRUSEC emergency access

NIRUSEC must never be the only thing standing between you and a local console.
The safe recovery path is intentionally simple and does not require a GUI.

## Local console

At the machine (or through a KVM/IPMI/serial console):

```sh
sudo /usr/local/libexec/nirusec-helper safe-mode
```

Run it through the installed fixed helper (or, from a development checkout,
`sudo /home/niru/.local/bin/nirusec --safe-mode`). It:

1. backs up the complete `/etc/ufw` tree under `/var/backups/nirusec/`,
2. resets UFW to a minimal recovery policy,
3. allows loopback and `tailscale0`,
4. allows SSH on port 22 so the machine can be reached again,
5. allows Tailscale direct UDP 41641,
6. enables UFW.

Safe mode is deliberately more open than a normal profile. Confirm the
machine is reachable, then repair the real rules or restore a backup. It also works through the NIRUSEC Firewall view's **Emergency safe mode**
button.

## Restore the previous UFW files

```sh
sudo /usr/local/libexec/nirusec-helper restore-ufw
```

This restores the most recent NIRUSEC backup in `/var/backups/nirusec/`,
disabling UFW while the files are copied and enabling it again. Backups are
root-only and never written to Git or the user state directory.

## If Tailscale or SSH is the problem

```sh
sudo systemctl status tailscaled ssh
sudo systemctl restart tailscaled ssh
sudo ufw allow in on tailscale0
sudo fail2ban-client unban --all   # only when fail2ban is installed
```

If a lock screen or display manager is in the way, use another TTY, a local
console or the machine's physical keyboard. A network-only rescue path cannot
guarantee access when the network itself is broken.

## Non-negotiables

- Never remove `loopback` or the Tailscale management path from all profiles.
- Always test a firewall change from a second SSH session before closing the
  first one.
- Keep a physical console or an out-of-band KVM path for remote-only machines.
- Keep one offline break-glass SSH key under your control; never commit it.
- A timer/watchdog that reverts a bad profile is safer than a hidden backdoor.
