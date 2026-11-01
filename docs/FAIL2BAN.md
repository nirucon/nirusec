# Fail2ban guidance

Fail2ban is useful for exposed password SSH, but it is not a substitute for
key authentication, a restrictive firewall and Tailscale ACLs.

A conservative starting point for sshd on Debian/Arch:

```ini
# /etc/fail2ban/jail.d/nirux-sshd.local
[sshd]
enabled = true
backend = systemd
maxretry = 8
findtime = 15m
bantime = 10m
# Local and trusted Tailscale addresses. Adjust only with a clear policy.
ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10
```

On Void/runit, use the fail2ban backend available for the installed logging
setup instead of `backend = systemd`, and verify `/var/log/auth.log` or the
journal source before relying on bans.

Why 8 rather than 5: agents and automation can mistype a password a few times.
A short `bantime` avoids a long lockout; `ignoreip` for the trusted tailnet
prevents a single failing agent from banning your Tailscale address. If the
tailnet is not strongly trusted, remove that range and keep key-only SSH
instead.

NIRUSEC does **not** enable fail2ban automatically. It should show fail2ban
status and current bans in a later version; installing a service that can
change authentication reachability is an explicit administrator decision.
