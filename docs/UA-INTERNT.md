# Using NIRUSEC on niruxwork at UA Internt

`niruxwork` may be used at Uddevalla kommun over the UA Internt network. That
environment can change the default route and DNS, and Tailscale may be
temporarily unavailable. Preserve more than one access path.

## Recommended UFW scope

The USB Wi-Fi interface used by `ua-net` is allowed to reach SSH and DHCP.
The exact interface name is stable from its MAC but should be checked:

```sh
ip -brief link
sudo ufw allow in on <ua-usb-interface> to any port 22 proto tcp
sudo ufw allow in on <ua-usb-interface> to any port 68 proto udp
```

The current `niruxwork` rule also keeps `tailscale0` trusted and limits ordinary
LAN SSH to the home subnet. UA internal resources are reached as outgoing
traffic, so they do not need broad inbound rules.

## Workflow at the workplace

```sh
# Keep Tailscale/DNS and the home default route; add UA routes only.
sudo ./ua-net up --dhcp

# When the full UA network really must be primary:
sudo ./ua-net up --primary --yes

# Always restore the previous DNS/routing before leaving:
sudo ./ua-net down
```

`--dhcp` is usually the better default for using internal UA resources while
keeping Tailscale and home DNS available. `--primary` changes the default route;
verify SSH/Tailscale immediately and keep a local session open.

If Tailscale is blocked or offline, use SSH to the current UA address on the
USB interface. Use `ip -4 addr show <ua-usb-interface>` to find it, and verify
the rule with `sudo ufw status verbose`. Never expose a public SSH rule just to
make UA work.

`ua-net down` should be run before switching back to home networking. Do not
store UA PFX files, private keys, passwords, internal hostnames or addresses in
this repository or in public NIRUSEC logs.
