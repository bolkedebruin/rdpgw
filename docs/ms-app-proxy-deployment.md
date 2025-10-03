# Microsoft Azure Application Proxy Deployment Guide

This guide provides step-by-step instructions for deploying RDPGW behind Microsoft Azure Application Proxy with Conditional Access Policy enforcement.

## Architecture Overview

```
Internet → Azure AD (Auth + CAP) → App Proxy → RDPGW (Internal) → RDP Hosts
```

**Authentication Flow:**
- **Web requests** (`/connect`): Full Azure AD authentication with headers
- **RDP protocol** (`/remoteDesktopGateway/`): Passthrough with token validation

## Prerequisites

- Azure AD Premium P1/P2 (for Conditional Access)
- Azure AD Application Proxy connector installed
- RDPGW deployed internally
- Network connectivity from connector to RDPGW

## Step 1: Azure AD App Registration

```powershell
# Create app registration
$app = New-AzADApplication -DisplayName "RDPGW-AppProxy" `
    -HomePage "https://rdpgw.yourdomain.com" `
    -IdentifierUris "https://rdpgw.yourdomain.com"

# Note the Application ID
Write-Host "Application ID: $($app.ApplicationId)"
```

## Step 2: Configure Application Proxy

### Portal Configuration

1. **Navigate to**: Azure AD → Enterprise Applications → New Application
2. **Select**: On-premises application
3. **Configure**:
   - **Name**: RDPGW
   - **Internal URL**: `http://rdpgw-server:80`
   - **External URL**: `https://rdpgw.yourdomain.com`
   - **Pre-authentication**: Azure Active Directory
   - **Connector Group**: Select appropriate connector

### Advanced Configuration

```json
{
  "application": {
    "name": "RDPGW",
    "internalUrl": "http://rdpgw-server",
    "externalUrl": "https://rdpgw.yourdomain.com",
    "preAuthentication": "aadPreAuthentication",
    "externalAuthenticationType": "aadPreAuthentication",
    "applicationProxyUrlSettings": {
      "externalUrl": "https://rdpgw.yourdomain.com",
      "internalUrl": "http://rdpgw-server",
      "isTranslateHostHeaderEnabled": true,
      "isTranslateLinksInBodyEnabled": false,
      "isOnPremPublishingEnabled": true
    }
  }
}
```

## Step 3: Configure Passthrough for RDP Endpoint

**Critical**: Configure App Proxy to bypass authentication for RDP connections:

### PowerShell Configuration

```powershell
# Get the application
$app = Get-AzADApplication -DisplayName "RDPGW-AppProxy"

# Configure passthrough paths (if available via API)
# Note: This may need to be configured via Support ticket
$passthroughPaths = @("/remoteDesktopGateway/*")
```

### Support Request

If passthrough configuration isn't available in portal:

1. **Open Azure Support Ticket**
2. **Request**: Passthrough configuration for `/remoteDesktopGateway/*` path
3. **Provide**: Application ID and external URL
4. **Reason**: RDP client compatibility requirements

## Step 4: RDPGW Configuration

### Complete Configuration File

```yaml
# rdpgw.yaml
Server:
  Authentication:
    - header
  Tls: disable
  GatewayAddress: https://rdpgw.yourdomain.com
  Port: 80
  Hosts:
    - server1.internal.domain:3389
    - server2.internal.domain:3389
    - "{{ preferred_username }}-desktop:3389"  # Dynamic host mapping

Header:
  UserHeader: "X-MS-CLIENT-PRINCIPAL-NAME"
  UserIdHeader: "X-MS-CLIENT-PRINCIPAL-ID"
  EmailHeader: "X-MS-CLIENT-PRINCIPAL-EMAIL"

Security:
  VerifyClientIp: false
  PAATokenSigningKey: "your-32-character-signing-key-here"
  PAATokenEncryptionKey: "your-32-character-encryption-key"

Caps:
  TokenAuth: true
  IdleTimeout: 60

Client:
  UsernameTemplate: "{{ username }}\x1f{{ token }}"
```

### Docker Deployment

```yaml
# docker-compose.yml
services:
  rdpgw:
    image: bolkedebruin/rdpgw:latest
    ports:
      - "80:443"
    volumes:
      - ./rdpgw.yaml:/app/rdpgw.yaml:ro
    environment:
      - RDPGW_SERVER__TLS=disable
      - RDPGW_SERVER__PORT=443
    networks:
      - internal

networks:
  internal:
    driver: bridge
```

## Step 5: Conditional Access Policy

### Create CAP for RDPGW

```powershell
# PowerShell example (simplified)
$conditions = @{
    "applications" = @{
        "includeApplications" = @($app.ApplicationId)
    }
    "users" = @{
        "includeGroups" = @("rdp-users-group-id")
    }
    "locations" = @{
        "includeLocations" = @("AllTrusted")
    }
}

$grantControls = @{
    "operator" = "OR"
    "builtInControls" = @("mfa", "compliantDevice")
}
```

### Portal Configuration

1. **Navigate to**: Azure AD → Security → Conditional Access
2. **Create Policy**:
   - **Name**: RDPGW Access Control
   - **Users**: Select appropriate groups
   - **Cloud apps**: Select RDPGW application
   - **Conditions**: Configure as needed (device, location, etc.)
   - **Grant**: Require MFA + Compliant Device
   - **Session**: Configure session lifetime

## Step 6: Testing

### Test Web Authentication

```bash
# Test /connect endpoint
curl -v https://rdpgw.yourdomain.com/connect
# Should redirect to Azure AD login
```

### Test RDP Connection

1. **Access web interface**: `https://rdpgw.yourdomain.com/connect`
2. **Authenticate**: Complete Azure AD login + MFA
3. **Download RDP file**: Should contain token-based credentials
4. **Connect via RDP client**: Should work without additional authentication

### Verify Headers

Check that App Proxy forwards correct headers:

```bash
# From internal network, test RDPGW directly
curl -H "X-MS-CLIENT-PRINCIPAL-NAME: user@domain.com" \
     http://rdpgw-server/connect
```

## Troubleshooting

### Common Issues

1. **RDP Client Won't Connect**:
   - Verify passthrough configuration for `/remoteDesktopGateway/*`
   - Check token generation in downloaded RDP file
   - Ensure `TokenAuth: true` in configuration

2. **Authentication Loop**:
   - Verify header configuration matches App Proxy headers
   - Check `VerifyClientIp: false` setting
   - Validate App Proxy connector connectivity

3. **CAP Not Enforced**:
   - Verify policy targets correct application
   - Check user/group assignments
   - Review conditional access logs

### Debug Commands

```bash
# Check RDPGW logs
docker logs rdpgw-container

# Test internal connectivity
curl -H "X-MS-CLIENT-PRINCIPAL-NAME: test@domain.com" \
     http://rdpgw-internal/connect

# Verify token generation
curl -v https://rdpgw.yourdomain.com/connect
```

### Azure AD Logs

Monitor these logs for authentication issues:

- **Sign-ins**: User authentication events
- **Conditional Access**: Policy evaluation results
- **Application Proxy**: Connector and application events

## Security Considerations

- **Network Isolation**: Deploy RDPGW in private network
- **Connector Security**: Ensure App Proxy connector is secured
- **Token Validation**: Monitor for token replay attacks
- **Audit Logging**: Enable comprehensive logging for compliance
- **Certificate Management**: Ensure proper TLS certificate chain
