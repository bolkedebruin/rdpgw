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

# AIM
RDPGW aims to provide a full open source replacement for MS Remote Desktop Gateway, 
including access policies.

# Security requirements

Several security requirements are stipulated by the client that is connecting to it and some are
enforced by the gateway. The client requires that the server's TLS certificate is valid and that
it is signed by a trusted authority. In addition, the common name in the certificate needs to
match the DNS hostname of the gateway. If these requirements are not met the client will refuse
to connect.

The gateway has several security phases. In the authentication phase the client's credentials are
verified. Depending the authentication mechanism used, the client's credentials are verified against
an OpenID Connect provider, Kerberos, a local PAM service, a local database, or extracted from HTTP headers
provided by upstream proxy services.

If OpenID Connect is used the user will
need to connect to a webpage provided by the gateway to authenticate, which in turn will redirect
the user to the OpenID Connect provider. If the authentication is successful the browser will download
a RDP file with temporary credentials that allow the user to connect to the gateway by using a remote
desktop client.

If Kerberos is used the client will need to have a valid ticket granting ticket (TGT). The gateway
will proxy the TGT request to the KDC. Therefore, the gateway needs to be able to connect to the KDC
and a krb5.conf file needs to be provided. The proxy works without the need for an RDP file and thus
the client can connect directly to the gateway.

If local authentication is used the client will need to provide a username and password that is verified
against PAM. This requires, to ensure privilege separation, that ```rdpgw-auth``` is also running and a
valid PAM configuration is provided per typical configuration.

If NTLM authentication is used, the allowed user credentials for the gateway should be configured in the 
configuration file of `rdpgw-auth`.

Finally, RDP hosts that the client wants to connect to are verified against what was provided by / allowed by
the server. Next to that the client's ip address needs to match the one it obtained the gateway token with if
using OpenID Connect. Due to proxies and NAT this is not always possible and thus can be disabled. However, this
is a security risk.

# Configuration
The configuration is done through a YAML file. The configuration file is read from `rdpgw.yaml` by default.
At the bottom of this README is an example configuration file. In these sections you will find the most important
settings.

## Authentication

RDPGW wants to be secure when you set it up from the start. It supports several authentication
mechanisms such as OpenID Connect, Kerberos, PAM, NTLM, and header-based authentication for proxy integration.

Technically, cookies are encrypted and signed on the client side relying
on [Gorilla Sessions](https://www.gorillatoolkit.org/pkg/sessions). PAA tokens (gateway access tokens)
are generated and signed according to the JWT spec by using [jwt-go](https://github.com/dgrijalva/jwt-go)
signed with a 256 bit HMAC. 

### Multi Factor Authentication (MFA)
RDPGW provides multi-factor authentication out of the box with OpenID Connect integration. Thus
you can integrate your remote desktops with Keycloak, Okta, Google, Azure, Apple or Facebook
if you want.

### Mixing authentication mechanisms

It is technically possible to mix authentication mechanisms. Currently, you can mix local with Kerberos or NTLM. If you enable 
OpenID Connect it is not possible to mix it with local or Kerberos at the moment.

### OpenID Connect

For detailed OpenID Connect setup with providers like Keycloak, Azure AD, Google, and others, see the [OpenID Connect Authentication Documentation](docs/openid-authentication.md).

### Kerberos

For detailed Kerberos setup including keytab generation, DNS requirements, and KDC proxy configuration, see the [Kerberos Authentication Documentation](docs/kerberos-authentication.md).


### PAM/Local Authentication

For detailed PAM setup including LDAP integration, container deployment, and compatible clients, see the [PAM Authentication Documentation](docs/pam-authentication.md).

### NTLM Authentication

For detailed NTLM setup including user management, security considerations, and deployment options, see the [NTLM Authentication Documentation](docs/ntlm-authentication.md).

### Header Authentication (Proxy Integration)

RDPGW supports header-based authentication for integration with reverse proxy services (Azure App Proxy, Google IAP, AWS ALB, etc.) that handle authentication upstream and pass user identity via HTTP headers.

For detailed configuration and examples, see the [Header Authentication Documentation](docs/header-authentication.md).

## TLS

The gateway requires a valid TLS certificate. This means a certificate that is signed by a valid CA that is in the store 
of your clients. If this is not the case particularly Windows clients will fail to connect. You can either provide a 
certificate and key file or let the gateway obtain a certificate from letsencrypt. If you want to use letsencrypt make 
sure that the host is reachable on port 80 from the letsencrypt servers.

For letsencrypt:

```yaml
Tls: auto
```

for your own certificate:
```yaml
Tls: enable
CertFile: server.pem 
KeyFile: key.pem
```

__NOTE__: You can disable TLS on the gateway, but you will then need to make sure a proxy is run in front of it that does
TLS termination. 


## Example configuration file for Open ID Connect

```yaml
# web server configuration. 
Server:
 # can be set to openid, kerberos, local and ntlm. If openid is used rdpgw expects
 # a configured openid provider, make sure to set caps.tokenauth to true. If local
 # rdpgw connects to rdpgw-auth over a socket to verify users and password. Note:
 # rdpgw-auth needs to be run as root or setuid in order to work. If kerberos is
 # used a keytab and krb5conf need to be supplied. local can be stacked with 
 # kerberos or ntlm authentication, so that the clients selects what it wants.
 Authentication:
  # - kerberos
  # - local
  - openid
  # - ntlm
 # The socket to connect to if using local auth. Ensure rdpgw auth is configured to
 # use the same socket.
 # AuthSocket: /tmp/rdpgw-auth.sock
 # Basic auth timeout (in seconds). Useful if you're planning on waiting for MFA
 BasicAuthTimeout: 5
 # The default option 'auto' uses a certificate file if provided and found otherwise
 # it uses letsencrypt to obtain a certificate, the latter requires that the host is reachable
 # from letsencrypt servers. If TLS termination happens somewhere else (e.g. a load balancer)
 # set this option to 'disable'. This is mutually exclusive with 'authentication: local'
 # Note: rdp connections over a gateway require TLS
 Tls: auto
 # gateway address advertised in the rdp files and browser
 GatewayAddress: localhost
 # port to listen on (change to 80 or equivalent if not using TLS)
 Port: 443
 # list of acceptable desktop hosts to connect to
 Hosts:
  - localhost:3389
  - my-{{ preferred_username }}-host:3389
 # if true the server randomly selects a host to connect to
 # valid options are: 
 #  - roundrobin, which selects a random host from the list (default)
 #  - signed, a listed host specified in the signed query parameter
 #  - unsigned, a listed host specified in the query parameter
 #  - any, insecurely allow any host specified in the query parameter
 HostSelection: roundrobin 
 # a random strings of at least 32 characters to secure cookies on the client
 # make sure to share this across the different pods
 SessionKey: thisisasessionkeyreplacethisjetzt
 SessionEncryptionKey: thisisasessionkeyreplacethisnunu!
  # where to store session details. This can be either file or cookie (default: cookie)
  # if a file store is chosen, it is required to have clients 'keep state' to the rdpgw
  # instance they are connected to.
 SessionStore: cookie
  # tries to set the receive / send buffer of the connections to the client
 # in case of high latency high bandwidth the defaults set by the OS might
 # be to low for a good experience
 # ReceiveBuf: 12582912
 # SendBuf: 12582912 
# Open ID Connect specific settings
OpenId:
 ProviderUrl: http://keycloak/auth/realms/test
 ClientId: rdpgw
 ClientSecret: your-secret
# Kerberos:
#  Keytab: /etc/keytabs/rdpgw.keytab
#  Krb5conf: /etc/krb5.conf
#  enabled / disabled capabilities
Caps:
 SmartCardAuth: false
 # required for openid connect
 TokenAuth: true
 # connection timeout in minutes, 0 is limitless
 IdleTimeout: 10
 EnablePrinter: true
 EnablePort: true
 EnablePnp: true
 EnableDrive: true
 EnableClipboard: true
Client:
  # template rdp file to use for clients
  # rdp file settings and their defaults see here: 
  # https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/rdp-files
  defaults: /etc/rdpgw/default.rdp
  # this is a go string templated with {{ username }} and {{ token }}
  # the example below uses the ASCII field separator to distinguish
  # between user and token 
  UsernameTemplate: "{{ username }}@bla.com\x1f{{ token }}"
  # If true puts splits "user@domain.com" into the user and domain component so that
  # domain gets set in the rdp file and the domain name is stripped from the username
  SplitUserDomain: false
  # If true, removes "username" (and "domain" if SplitUserDomain is true) from RDP file.
  # NoUsername: true
  # If both SigningCert and SigningKey are set the downloaded RDP file will be signed
  # so the client can authenticate the validity of the RDP file and reduce warnings from
  # the client if the CA that issued the certificate is trusted. Both should be PEM encoded
  # and the key must be an unencrypted RSA private key.
  # SigningCert: /path/to/signing.crt
  # SigningKey: /path/to/signing.key
Security:
  # a random string of 32 characters to secure cookies on the client
  # make sure to share this amongst different pods
  PAATokenSigningKey: thisisasessionkeyreplacethisjetzt
  # PAATokenEncryptionKey: thisisasessionkeyreplacethisjetzt
  # a random string of 32 characters to secure cookies on the client
  UserTokenEncryptionKey: thisisasessionkeyreplacethisjetzt
  # Signing makes the token bigger and we are limited to 511 characters
  # UserTokenSigningKey: thisisasessionkeyreplacethisjetzt
  # if you want to enable token generation for the user
  # if true the username will be set to a jwt with the username embedded into it
  EnableUserToken: true
  # Verifies if the ip used to connect to download the rdp file equals from where the
  # connection is opened.
  VerifyClientIp: true
```

## How to build & install

__NOTE__: a [docker image](https://hub.docker.com/r/bolkedebruin/rdpgw/) is available on docker hub, which removes the need for building and installing go.

Ensure that you have `make` (comes with standard build tools, like `build-essential` on Debian), `go` (version 1.19 or above), and development files for PAM (`libpam0g-dev` on Debian) installed.

Then clone the repo and issues the following.

```bash
cd rdpgw
make
make install
```

## Testing locally
A convenience docker-compose allows you to test the RDPGW locally. It uses [Keycloak](http://www.keycloak.org) 
and [xrdp](http://www.xrdp.org) and exposes it services on port 9443. You will need to allow your browser
to connect to localhost with and self signed security certificate. For chrome set `chrome://flags/#allow-insecure-localhost`.
The username to login to both Keycloak and xrdp is `admin` as is the password.

__NOTE__: The redirecting relies on DNS. Make sure to add ``127.0.0.1	keycloak`` to your `/etc/hosts` file to ensure
that the redirect works.

__NOTE__: The local testing environment uses a self signed certificate. This works for MAC clients, but not for Windows.
If you want to test it on Windows you will need to provide a valid certificate.

```bash
# with open id
cd dev/docker
docker-compose -f docker-compose.yml up

# or for arm64 with open id
docker-compose -f docker-compose-arm64.yml up

# or for local or pam
docker-compose -f docker-compose-local.yml up
```
    
You can then connect to the gateway at `https://localhost:9443/connect` for the OpenID connect flavors which will start 
the authentication flow. Or you can connect directly with the gateway set and the host set to ``xrdp`` if using the ``local`` 
flavor. You can login with 'admin/admin'. The RDP file will download and you can open it with a remote 
desktop client. Also for logging in 'admin/admin' will work.

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

## Client Caveats
The several clients that Microsoft provides come with their own caveats. 
The most important one is that the default client on Windows ``mstsc`` does 
not support basic authentication. This means you need to use either OpenID Connect,
Kerberos or ntlm authentication.

In addition to that, ``mstsc``, when configuring a gateway directly in the client requires
you to either:
 * "save the credentials" for the gateway
 * or specify a (random) domain name in the username field (e.g. ``.\username``) when prompted for the gateway credentials,
 
otherwise the client will not connect at all (it won't send any packages to the gateway) and it will keep on asking for new credentials.

Finally, ``mstsc`` requires a valid certificate on the gateway.

The Microsoft Remote Desktop Client from the Microsoft Store does not have these issues,
but it requires that the username and password used for authentication are the same for
both the gateway and the RDP host.

The Microsoft Remote Desktop Client for Mac does not have these issues and is the most flexible.
It supports basic authentication, OpenID Connect and Kerberos and can use different credentials

The official Microsoft IOS and Android clients seem also more flexible.

Third party clients like [FreeRDP](https://www.freerdp.com) might also provide more
flexibility.

## TODO
* Improve Web Interface

# Acknowledgements
* This product includes software developed by the Thomson Reuters Global Resources. ([go-ntlm](https://github.com/m7913d/go-ntlm) - BSD-4 License)
