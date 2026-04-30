# Upgrading

## Unreleased

### `hostselection: any` now refuses non-routable destinations and non-RDP ports by default

Previously, when `server.hostselection: any` was set, rdpgw forwarded
to whatever `?host=` value the request carried with no check on the
target. The gateway would happily relay TCP traffic to loopback,
RFC1918, link-local, or arbitrary high-numbered ports on public hosts.

After upgrading, `any` mode rejects any destination that resolves to a
loopback / RFC1918 / link-local / IPv6 ULA / unspecified / multicast
address, and any port that is not in `AllowedDestinationPorts`. The
default port allow-list is `[3389]`.

If your deployment legitimately reaches private destinations or extra
ports through `any` mode, opt back in:

```yaml
Server:
  HostSelection: any
  AllowedDestinationPorts:
    - 3389
    - 5985        # add what you actually need
  AllowPrivateDestinations: true
```

The other host-selection modes (`roundrobin`, `signed`, `unsigned`)
already use the operator-curated `Server.Hosts` allow-list and are
unaffected by this change.

# Upgrading from 1.X to 2.0

In 2.0 the options for configuring client side RDP settings have been removed in favor of template file.
The template file is a RDP file that is used as a template for the connection. The template file is parsed 
and a few settings are replaced to ensure the client can connect to the server and the correct domain is used.

The format of the template file is as follows:

```
# <setting>:<type i or s>:<value>
domain:s:testdomain
connection type:i:2
```

The filename is set under `client > defaults`.
