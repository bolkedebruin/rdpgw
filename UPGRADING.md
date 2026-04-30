# Upgrading

## Unreleased

### `rdpgw-auth` only accepts connections from the daemon's own UID by default

The auth daemon previously created its socket world-writable
(`Umask(0)`) and accepted any local UID that could `connect(2)` to it.
Two changes:

* The socket is now created with mode `0660` (no access for `other`).
* The daemon reads `SO_PEERCRED` on every accepted connection and
  rejects callers whose UID is not on the allow-list. The default
  allow-list is the daemon's own UID.

If `rdpgw` and `rdpgw-auth` run as the same user, no action is
required. Otherwise, list the gateway's UID (or a shared GID):

```
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-uid 1001
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-gid 1100
```

`--allow-uid` and `--allow-gid` are repeatable.

### `X-Forwarded-For` is no longer trusted by default

Previously rdpgw read the first `X-Forwarded-For` entry into the
request identity unconditionally. The resulting client IP attribute is
later compared against the value embedded in the gateway access
cookie, so any caller reaching rdpgw directly could set
`X-Forwarded-For` to any value and steer that binding.

After upgrading, `X-Forwarded-For` is honored only when the request
arrives from a `Server.TrustedProxies` CIDR. Otherwise the client IP
comes from `r.RemoteAddr`. The default `Server.TrustedProxies` is
empty, so by default `X-Forwarded-For` is ignored entirely.

If your deployment fronts rdpgw with a reverse proxy or load balancer
on a known subnet, list it:

```yaml
Server:
  TrustedProxies:
    - 10.0.0.0/8        # the proxy's egress subnet
```

If no proxy fronts rdpgw, leave `TrustedProxies` empty -- the
request's `RemoteAddr` is the right source for client identity in
that case.

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
