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
Server:
  Authentication:
    - header
  Tls: disable  # App Proxy handles TLS termination

Header:
  UserHeader: "X-MS-CLIENT-PRINCIPAL-NAME"
  UserIdHeader: "X-MS-CLIENT-PRINCIPAL-ID"
  EmailHeader: "X-MS-CLIENT-PRINCIPAL-EMAIL"

Security:
  VerifyClientIp: false  # Required for App Proxy

Caps:
  TokenAuth: true  # Essential for RDP client connections
```

**Azure Configuration:**

1. **Create App Registration** in Azure AD:
   ```bash
   # Note the Application ID for App Proxy configuration
   az ad app create --display-name "RDPGW-AppProxy"
   ```

2. **Configure Application Proxy**:
   - **Internal URL**: `http://rdpgw-internal:80` (or your internal RDPGW address)
   - **External URL**: `https://rdpgw.yourdomain.com`
   - **Pre-authentication**: Azure Active Directory
   - **Pass through**: Enabled for `/remoteDesktopGateway/`

3. **Configure Conditional Access Policies**:
   - Target the RDPGW App Proxy application
   - Set device compliance, location restrictions, MFA requirements
   - Enable session controls as needed

**Important App Proxy Configuration:**

```json
{
  "name": "RDPGW",
  "internalUrl": "http://rdpgw-internal",
  "externalUrl": "https://rdpgw.yourdomain.com",
  "preAuthenticatedApplication": {
    "preAuthenticationType": "AzureActiveDirectory",
    "passthroughPaths": [
      "/remoteDesktopGateway/*"
    ]
  }
}
```

**Authentication Flow:**

1. **Web Authentication** (`/connect` endpoint):
   ```
   User Browser → App Proxy (Azure AD auth) → RDPGW → Downloads RDP file
   ```

2. **RDP Client Connection** (`/remoteDesktopGateway/` endpoint):
   ```
   RDP Client → App Proxy (passthrough) → RDPGW (token validation) → RDP Host
   ```

**Key Requirements:**
- **Passthrough configuration** for `/remoteDesktopGateway/` path
- **Header authentication** only for `/connect` endpoint
- **Token-based auth** for actual RDP connections
- **Disable IP verification** due to App Proxy NAT

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
upstream rdpgw {
    server rdpgw:443;
}

upstream auth-service {
    server auth-service:80;
}

server {
    listen 443 ssl http2;
    server_name your-gateway.example.com;

    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Auth endpoint (internal)
    location /auth {
        internal;
        proxy_pass http://auth-service;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Main location with auth and WebSocket support
    location / {
        # Authentication
        auth_request /auth;
        auth_request_set $user $upstream_http_x_auth_user;
        auth_request_set $email $upstream_http_x_auth_email;

        # Forward user headers to RDPGW
        proxy_set_header X-Auth-User $user;
        proxy_set_header X-Auth-Email $email;

        # WebSocket and HTTP upgrade support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for long-lived connections
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;

        # Disable buffering for real-time protocols
        proxy_buffering off;

        proxy_pass https://rdpgw;
    }
}

# WebSocket upgrade mapping
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
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
