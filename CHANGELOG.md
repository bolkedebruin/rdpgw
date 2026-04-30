# Changelog

All user-visible changes to rdpgw will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `X-Forwarded-For` is now honored only when the request arrives from
  a `Server.TrustedProxies` CIDR. The default `Server.TrustedProxies`
  is empty, so by default the request's `RemoteAddr` (host portion) is
  the source of `AttrClientIp`. See [UPGRADING.md](UPGRADING.md) if
  your deployment relies on a fronting proxy stamping XFF.
- `server.hostselection: any` now refuses destinations that resolve to
  loopback, RFC1918, link-local, IPv6 ULA, unspecified, or multicast
  addresses, and only forwards to ports in `Server.AllowedDestinationPorts`
  (default `[3389]`). Operators that need the old behavior can opt back in
  with `Server.AllowPrivateDestinations: true` and an extended port list.
  See [UPGRADING.md](UPGRADING.md) for migration notes. The other
  host-selection modes (`roundrobin`, `signed`, `unsigned`) already used
  the operator-curated `Server.Hosts` list and are unaffected.

### Added

- `Server.TrustedProxies` (`[]string`, CIDR, default empty).
- `Server.AllowedDestinationPorts` (`[]int`, default `[3389]`).
- `Server.AllowPrivateDestinations` (`bool`, default `false`).
