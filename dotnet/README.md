# RDPGW — C# / .NET 10 port

This directory contains a port of the Go implementation of RDPGW (an open source
[MS-TSGU](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/0007d661-a86d-4e8f-89f7-7f77f8824188)
Remote Desktop Gateway) to C# targeting .NET 10.

## Layout

| Project | Go equivalent | Description |
| --- | --- | --- |
| `src/Rdpgw` | `cmd/rdpgw` | The gateway itself: MS-TSGU protocol handling (WebSocket and legacy `RDG_IN_DATA`/`RDG_OUT_DATA` transports), OpenID Connect / basic / NTLM / header / Kerberos authentication, PAA (JWT) token handling, RDP file generation, KDC proxy (MS-KKDCP), web interface and Prometheus metrics. |
| `src/Rdpgw.Auth` | `cmd/auth` | The privilege-separated authentication daemon (`rdpgw-auth`): gRPC over a unix domain socket offering PAM, local user database and NTLM authentication. |
| `src/Rdpgw.Shared` | `shared/auth` + `proto/auth.proto` | The gRPC contract shared between the gateway and the authentication daemon, generated from `auth.proto`. |

## Building

Requires the .NET 10 SDK.

```sh
cd dotnet
dotnet build
```

To publish self-contained binaries:

```sh
dotnet publish src/Rdpgw -c Release -o out/rdpgw
dotnet publish src/Rdpgw.Auth -c Release -o out/rdpgw-auth
```

## Running

The programs use the same YAML configuration files, environment variable
overrides (`RDPGW_` prefix, `__` as section separator), command line flags,
endpoints (`/remoteDesktopGateway/`, `/connect`, `/callback`, `/tokeninfo`,
`/KdcProxy`, `/metrics`, `/api/v1/...`) and gRPC socket protocol as the Go
implementation, so the existing documentation in the repository root applies.

```sh
./rdpgw -c rdpgw.yaml
./rdpgw-auth -c rdpgw-auth.yaml
```

## Parity notes / known differences

* **ACME / Let's Encrypt**: the Go version can obtain certificates
  automatically via `golang.org/x/crypto/acme/autocert`. The .NET port does not
  bundle an ACME client; configure `server.certfile`/`server.keyfile` or run
  behind a TLS terminator (`server.tls: disable`).
* **Session storage**: the Go version uses Gorilla sessions (cookie or
  filesystem backed). The port uses cookie sessions encrypted with the
  configured session keys.
* **Kerberos**: the gateway relies on `Microsoft.AspNetCore.Authentication.Negotiate`
  (which uses MIT Kerberos on Linux, e.g. via `KRB5_KTNAME`) instead of a
  bundled SPNEGO implementation. The KDC proxy endpoint is ported natively.
* **Socket buffer tuning**: the Go version pokes `SO_RCVBUF`/`SO_SNDBUF` via
  reflection into the TLS connection; the port sets buffers through the socket
  API where available and otherwise ignores the setting.
* **User session serialization** uses JSON rather than Go's `gob` encoding, so
  sessions are not interchangeable between the Go and .NET binaries.
