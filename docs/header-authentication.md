# Header Authentication

RDPGW supports header-based authentication for integration with reverse proxy services that handle authentication upstream.

## Configuration

```yaml
Server:
  Authentication:
    - header
  Tls: disable  # Proxy handles TLS termination

Header:
  UserHeader: "X-Forwarded-User"        # Required: Username header
  UserIdHeader: "X-Forwarded-User-Id"   # Optional: User ID header
  EmailHeader: "X-Forwarded-Email"      # Optional: Email header
  DisplayNameHeader: "X-Forwarded-Name" # Optional: Display name header

Caps:
  TokenAuth: true

Security:
  VerifyClientIp: false  # Requests come through proxy
```

## Proxy Service Examples

### Microsoft Azure Application Proxy

```yaml
Header:
  UserHeader: "X-MS-CLIENT-PRINCIPAL-NAME"
  UserIdHeader: "X-MS-CLIENT-PRINCIPAL-ID"
  EmailHeader: "X-MS-CLIENT-PRINCIPAL-EMAIL"
```

**Setup**: Configure App Proxy to publish RDPGW with pre-authentication enabled. Users authenticate via Azure AD before reaching RDPGW.

### Google Cloud Identity-Aware Proxy (IAP)

```yaml
Header:
  UserHeader: "X-Goog-Authenticated-User-Email"
  UserIdHeader: "X-Goog-Authenticated-User-ID"
  EmailHeader: "X-Goog-Authenticated-User-Email"
```

**Setup**: Enable IAP on your Cloud Load Balancer pointing to RDPGW. Configure OAuth consent screen and authorized users/groups.

### AWS Application Load Balancer (ALB) with Cognito

```yaml
Header:
  UserHeader: "X-Amzn-Oidc-Subject"
  EmailHeader: "X-Amzn-Oidc-Email"
  DisplayNameHeader: "X-Amzn-Oidc-Name"
```

**Setup**: Configure ALB with Cognito User Pool authentication. Enable OIDC headers forwarding to RDPGW target group.

### Traefik with ForwardAuth

```yaml
Header:
  UserHeader: "X-Forwarded-User"
  EmailHeader: "X-Forwarded-Email"
  DisplayNameHeader: "X-Forwarded-Name"
```

**Setup**: Use Traefik ForwardAuth middleware with external auth service (e.g., OAuth2 Proxy, Authelia) that sets headers.

### nginx with auth_request

```yaml
Header:
  UserHeader: "X-Auth-User"
  EmailHeader: "X-Auth-Email"
```

**nginx config**:
```nginx
location /auth {
  internal;
  proxy_pass http://auth-service;
  proxy_set_header X-Original-URI $request_uri;
}

location / {
  auth_request /auth;
  auth_request_set $user $upstream_http_x_auth_user;
  auth_request_set $email $upstream_http_x_auth_email;
  proxy_set_header X-Auth-User $user;
  proxy_set_header X-Auth-Email $email;
  proxy_pass http://rdpgw;
}
```

## Security Considerations

- **Trust Boundary**: RDPGW trusts headers set by the proxy. Ensure the proxy cannot be bypassed.
- **Header Validation**: Configure proxy to strip/override user headers from client requests.
- **Network Security**: Deploy RDPGW in private network accessible only via the proxy.
- **TLS**: Enable TLS between proxy and RDPGW in production environments.

## Validation

Test header authentication:
```bash
curl -H "X-Forwarded-User: testuser@domain.com" \
     https://your-proxy/connect
```
