# Kerberos Authentication

![Kerberos](images/flow-kerberos.svg)

RDPGW supports Kerberos authentication via SPNEGO for seamless integration with Active Directory and other Kerberos environments.

## Important Notes

**⚠️ DNS Requirements**: Kerberos is heavily reliant on DNS (forward and reverse). Ensure your DNS is properly configured.

**⚠️ Error Messages**: Kerberos errors are not always descriptive. This documentation provides configuration guidance, but detailed Kerberos troubleshooting is beyond scope.

## Prerequisites

- Valid Kerberos environment (KDC/Active Directory)
- Proper DNS configuration (forward and reverse lookups)
- Service principal for the gateway
- Keytab file with appropriate permissions

## Configuration

### 1. Create Service Principal

Create a service principal for the gateway in your Kerberos realm:

```bash
# Active Directory
setspn -A HTTP/rdpgw.example.com@YOUR.REALM service-account

# MIT Kerberos
kadmin.local -q "addprinc -randkey HTTP/rdpgw.example.com@YOUR.REALM"
```

### 2. Generate Keytab

Use `ktutil` or similar tool to create a keytab file:

```bash
ktutil
addent -password -p HTTP/rdpgw.example.com@YOUR.REALM -k 1 -e aes256-cts-hmac-sha1-96
wkt rdpgw.keytab
quit
```

Place the keytab file in a secure location and ensure it's only readable by the gateway user:

```bash
sudo mv rdpgw.keytab /etc/keytabs/
sudo chown rdpgw:rdpgw /etc/keytabs/rdpgw.keytab
sudo chmod 600 /etc/keytabs/rdpgw.keytab
```

### 3. Configure krb5.conf

Ensure `/etc/krb5.conf` is properly configured:

```ini
[libdefaults]
    default_realm = YOUR.REALM
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    YOUR.REALM = {
        kdc = kdc.your.realm:88
        admin_server = kdc.your.realm:749
    }

[domain_realm]
    .your.realm = YOUR.REALM
    your.realm = YOUR.REALM
```

### 4. Gateway Configuration

```yaml
Server:
  Authentication:
    - kerberos
Kerberos:
  Keytab: /etc/keytabs/rdpgw.keytab
  Krb5conf: /etc/krb5.conf
Caps:
  TokenAuth: false
```

## Authentication Flow

1. Client connects to gateway with Kerberos ticket
2. Gateway validates ticket using keytab
3. Client connects directly without RDP file download
4. Gateway proxies TGT requests to KDC as needed

## KDC Proxy Support

RDPGW includes KDC proxy functionality for environments where clients cannot directly reach the KDC:

- Endpoint: `https://your-gateway/KdcProxy`
- Supports MS-KKDCP protocol
- Automatically configured when Kerberos authentication is enabled

## Client Configuration

### Windows Clients

Configure Windows clients to use the gateway's FQDN and ensure:
- Client can resolve gateway hostname
- Client time is synchronized with KDC
- Client has valid TGT

### Linux Clients

Ensure `krb5.conf` is configured and client has valid ticket:

```bash
kinit username@YOUR.REALM
klist  # Verify ticket
```

## Troubleshooting

### Common Issues

1. **Clock Skew**: Ensure all systems have synchronized time
2. **DNS Issues**: Verify forward/reverse DNS resolution
3. **Principal Names**: Ensure service principal matches gateway FQDN
4. **Keytab Permissions**: Verify keytab file permissions and ownership

### Debug Commands

```bash
# Test keytab
kinit -k -t /etc/keytabs/rdpgw.keytab HTTP/rdpgw.example.com@YOUR.REALM

# Verify DNS
nslookup rdpgw.example.com
nslookup <gateway-ip>

# Check time sync
ntpdate -q ntp.your.realm
```

### Log Analysis

Enable verbose logging in RDPGW and check for:
- Keytab loading errors
- Principal validation failures
- KDC communication issues

## Security Considerations

- Protect keytab files with appropriate permissions (600)
- Regularly rotate service account passwords
- Monitor for unusual authentication patterns
- Ensure encrypted communication (aes256-cts-hmac-sha1-96)
- Use specific service accounts, not user accounts
