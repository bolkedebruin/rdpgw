GO Remote Desktop Gateway
=========================

![Go](https://github.com/bolkedebruin/rdpgw/workflows/Go/badge.svg)

:star: Star us on GitHub — it helps!

RDPGW is an implementation of the [Remote Desktop Gateway protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsgu/0007d661-a86d-4e8f-89f7-7f77f8824188).
This allows you to connect with the official Microsoft clients to remote desktops over HTTPS. 
These desktops could be, for example, [XRDP](http://www.xrdp.org) desktops running in containers
on Kubernetes.

## AIM
RDPGW aims to provide a full open source replacement for MS Remote Desktop Gateway, 
including access policies.

## Multi Factor Authentication (MFA)
RDPGW provides multi factor authentication out of the box with OpenID Connect integration. Thus
you can integrate your remote desktops with Keycloak, Okta, Google, Azure, Apple or Facebook 
if you want. 

## Security
RDPGW wants to be secure when you set it up from the beginning. It does this by having OpenID
Connect integration enabled by default. Cookies are encrypted and signed on the client side relying
on [Gorilla Sessions](https://www.gorillatoolkit.org/pkg/sessions). PAA tokens (gateway access tokens)
are generated and signed according to the JWT spec by using [jwt-go](https://github.com/dgrijalva/jwt-go)
signed with a 256 bit HMAC. Hosts provided by the user are verified against what was provided by
the server. Finally, the client's ip address needs to match the one it obtained the token with.

## How to build
```bash
cd rdpgw
go build -o rdpgw .
```

## Configuration
By default the configuration is read from `rdpgw.yaml`. Below is a 
template.

```yaml
# web server configuration. 
server:
 # TLS certificate files (required)
 certFile: server.pem
 keyFile: key.pem
 # gateway address advertised in the rdp files
 gatewayAddress: localhost
 # port to listen on
 port: 443
 # list of acceptable desktop hosts to connect to
 hosts:
  - localhost:3389
  - my-{{ preferred_username }}-host:3389
  # Allow the user to connect to any host (insecure)
  - any 
 # if true the server randomly selects a host to connect to
 roundRobin: false 
 # a random strings of at least 32 characters to secure cookies on the client
 # make sure to share this across the different pods
 sessionKey: thisisasessionkeyreplacethisjetzt
 sessionEncryptionKey: thisisasessionkeyreplacethisnunu!
# Open ID Connect specific settings
openId:
 providerUrl: http://keycloak/auth/realms/test
 clientId: rdpgw
 clientSecret: your-secret
# enabled / disabled capabilities
caps:
 smartCardAuth: false
 tokenAuth: true
 # connection timeout in minutes, 0 is limitless
 idleTimeout: 10
 enablePrinter: true
 enablePort: true
 enablePnp: true
 enableDrive: true
 enableClipboard: true
client:
  usernameTemplate: "{{ username }}@bla.com"
  # rdp file settings see: 
  # https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files
  networkAutoDetect: 0
  bandwidthAutoDetect: 1
  ConnectionType: 6
security:
  # a random string of at least 32 characters to secure cookies on the client
  # make sure to share this amongst different pods
  tokenSigningKey: thisisasessionkeyreplacethisjetzt
```
## Local tests
```bash
cd dev/docker
docker-compose build
docker-compose up
```
Allow your browser to run on unsecure localhost.
For chrome
chrome://flags/#allow-insecure-localhost
Use admin:admin user password combination whenever asked.

## Use
Point your browser to `https://your-gateway/connect`. After authentication
and RDP file will download to your desktop. This file can be opened by one
of the remote desktop clients and it will try to connect to the gateway and
desktop host behind it.

## TODO
* Integrate Open Policy Agent
* Integrate GOKRB5
* Integrate uber-go/zap
* Integrate prometheus
* Research: TLS defragmentation 
* Improve Web Interface


