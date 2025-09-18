# OpenID Connect Authentication

![OpenID Connect](images/flow-openid.svg)

RDPGW supports OpenID Connect authentication for integration with identity providers like Keycloak, Okta, Google, Azure, Apple, or Facebook.

## Configuration

To use OpenID Connect, ensure you have properly configured your OpenID Connect provider with a client ID and secret. The client ID and secret authenticate the gateway to the OpenID Connect provider. The provider authenticates the user and provides the gateway with a token, which generates a PAA token for RDP host connections.

```yaml
Server:
  Authentication:
    - openid
OpenId:
  ProviderUrl: https://<provider_url>
  ClientId: <your_client_id>
  ClientSecret: <your_client_secret>
Caps:
  TokenAuth: true
```

## Authentication Flow

1. User navigates to `https://your-gateway/connect`
2. Gateway redirects to OpenID Connect provider for authentication
3. User authenticates with the provider (supports MFA)
4. Provider redirects back to gateway with authentication token
5. Gateway validates token and generates RDP file with temporary credentials
6. User downloads RDP file and connects using remote desktop client

## Multi-Factor Authentication (MFA)

RDPGW provides multi-factor authentication out of the box with OpenID Connect integration. Configure MFA in your identity provider to enhance security.

## Provider Examples

### Keycloak
```yaml
OpenId:
  ProviderUrl: https://keycloak.example.com/auth/realms/your-realm
  ClientId: rdpgw
  ClientSecret: your-keycloak-secret
```

### Azure AD
```yaml
OpenId:
  ProviderUrl: https://login.microsoftonline.com/{tenant-id}/v2.0
  ClientId: your-azure-app-id
  ClientSecret: your-azure-secret
```

### Google
```yaml
OpenId:
  ProviderUrl: https://accounts.google.com
  ClientId: your-google-client-id.googleusercontent.com
  ClientSecret: your-google-secret
```

## Security Considerations

- Always use HTTPS for production deployments
- Store client secrets securely and rotate them regularly
- Configure appropriate scopes and claims in your provider
- Enable MFA in your identity provider for enhanced security
- Set appropriate session timeouts in both gateway and provider

## Troubleshooting

- Ensure `ProviderUrl` is accessible from the gateway
- Verify redirect URI is configured in your provider (usually `https://your-gateway/callback`)
- Check that required scopes (openid, profile, email) are configured
- Validate that the provider's certificate is trusted by the gateway
