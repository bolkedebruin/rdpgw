GO Remote Desktop Gateway
=========================

![Go](https://github.com/bolkedebruin/rdpgw/workflows/Go/badge.svg)
[![Docker Pulls](https://badgen.net/docker/pulls/bolkedebruin/rdpgw?icon=docker&label=pulls)](https://hub.docker.com/r/bolkedebruin/rdpgw/)
[![Docker Stars](https://badgen.net/docker/stars/bolkedebruin/rdpgw?icon=docker&label=stars)](https://hub.docker.com/r/bolkedebruin/rdpgw/)
[![Docker Image Size](https://badgen.net/docker/size/bolkedebruin/rdpgw?icon=docker&label=image%20size)](https://hub.docker.com/r/bolkedebruin/rdpgw/)


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

## How to build & install
```bash
cd rdpgw
make
make install
```

## Configuration
By default the configuration is read from `rdpgw.yaml`. Below is a 
template.

```yaml
# web server configuration. 
server:
 # disable TLS if termination happens somehwere else (e.g. a load balancer)
 # note: rdp connections over a gateway require TLS
 disableTLS: false
 # TLS certificate files
 certFile: server.pem
 keyFile: key.pem
 # gateway address advertised in the rdp files
 gatewayAddress: localhost
 # port to listen on (change to 80 or equivalent if not using TLS)
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
  # where to store session details. This can be either file or cookie (default: cookie)
  # if a file store is chosen, it is required to have clients 'keep state' to the rdpgw
  # instance they are connected to.
 sessionStore: cookie
  # tries to set the receive / send buffer of the connections to the client
 # in case of high latency high bandwidth the defaults set by the OS might
 # be to low for a good experience
 # receiveBuf: 12582912
 # sendBuf: 12582912 
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
  # this is a go string templated with {{ username }} and {{ token }}
  # the example below uses the ASCII field separator to distinguish
  # between user and token 
  usernameTemplate: "{{ username }}@bla.com\x1f{{ token }}"
  # rdp file settings see: 
  # https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files
  networkAutoDetect: 0
  bandwidthAutoDetect: 1
  ConnectionType: 6
  # If true puts splits "user@domain.com" into the user and domain component so that
  # domain gets set in the rdp file and the domain name is stripped from the username
  SplitUserDomain: false
security:
  # a random string of at least 32 characters to secure cookies on the client
  # make sure to share this amongst different pods
  PAATokenSigningKey: thisisasessionkeyreplacethisjetzt
  # PAATokenEncryptionKey: thisisasessionkeyreplacethisjetzt
  UserTokenEncryptionKey: thisisasessionkeyreplacethisjetzt
  # if you want to enable token generation for the user
  # if true the username will be set to a jwt with the username embedded into it
  EnableUserToken: true
  # Verifies if the ip used to connect to download the rdp file equals from where the
  # connection is opened.
  VerifyClientIp: true
```
## Testing locally
A convenience docker-compose allows you to test the RDPGW locally. It uses [Keycloak](http://www.keycloak.org) 
and [xrdp](http://www.xrdp.org) and exposes it services on port 443. You will need to allow your browser
to connect to localhost with and self signed security certificate. For chrome set `chrome://flags/#allow-insecure-localhost`.
The username to login to both Keycloak and xrdp is `admin` as is the password.

```bash
cd dev/docker
docker-compose build
docker-compose up
```

## Use
Point your browser to `https://your-gateway/connect`. After authentication
and RDP file will download to your desktop. This file can be opened by one
of the remote desktop clients and it will try to connect to the gateway and
desktop host behind it.

## Integration
The gateway exposes an endpoint for the verification of user tokens at
https://yourserver/tokeninfo . The query parameter is 'access_token' so
you can just do a GET to https://yourserver/tokeninfo?access_token=<token> .
It will return 200 OK with the decrypted token.

In this way you can integrate, for example, it with [pam-jwt](https://github.com/bolkedebruin/pam-jwt).

## TODO
* Integrate Open Policy Agent
* Integrate GOKRB5
* Integrate uber-go/zap
* Research: TLS defragmentation 
* Improve Web Interface


