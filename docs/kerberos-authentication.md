# Kerberos Authentication

![Kerberos](images/flow-kerberos.svg)

RDPGW supports Kerberos authentication via SPNEGO for seamless integration with Active Directory and other Kerberos environments, including built-in KDC Proxy support (`/KdcProxy`) and stacked NTLM fallback.

## Important Notes

**⚠️ DNS Requirements**: Kerberos is heavily reliant on DNS (forward and reverse). Ensure your DNS is properly configured.

**⚠️ Error Messages**: Kerberos errors are not always descriptive. This documentation provides configuration guidance, but detailed Kerberos troubleshooting is beyond scope.

**⚠️ KDC Proxy Transport**: RDPGW's built-in KDC Proxy (`/KdcProxy`) prioritizes **TCP KDCs** over UDP. This prevents Active Directory `KRB5KRB_ERR_RESPONSE_TOO_BIG` errors that occur when tickets containing large PACs exceed the UDP 1,465-byte limit.

## Prerequisites

- Valid Kerberos environment (KDC/Active Directory)
- Proper DNS configuration (forward and reverse lookups)
- Service principal for the gateway
- Keytab file with appropriate permissions (ensure binary transfer without UTF-8 string mangling)

## Configuration

### 1. Configure krb5.conf

Before joining domains or generating keytabs, ensure `/etc/krb5.conf` is properly configured on the gateway:

```ini
[libdefaults]
    default_realm = YOUR.REALM
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    YOUR.REALM = {
        kdc = kdc1.your.realm:88
        kdc = kdc2.your.realm:88
        admin_server = kdc1.your.realm:749
        admin_server = kdc2.your.realm:749
    }

[domain_realm]
    .your.realm = YOUR.REALM
    your.realm = YOUR.REALM
```

> 💡 **Multiple KDCs / Domain Controllers**: If you need to specify multiple KDC or administration servers for redundancy, you can repeat the `kdc` and `admin_server` entries within the realm block.

### 2. Domain Join & Service Principal Creation

Service principals (SPNs) identify the gateway service in the Kerberos realm. Depending on your environment, choose one of the following methods:

#### Method A: Active Directory Domain Join & Samba (`net ads`)
When using `rdpgw-auth-winbind` or a domain-joined Linux gateway, joining the domain automatically creates the computer object and principal in Active Directory.
- **`net ads setspn add`**: Note that running `net ads setspn add` (or letting the container startup script automatically manage SPNs based on `GatewayAddress`) registers the SPN directly on the domain computer object in Active Directory on the Domain Controller (DC), not just locally in the keytab.

```bash
# Join domain (if not already joined via AD_JOIN_USER env var)
net ads join -U Administrator

# Register additional SPNs on the Active Directory Domain Controller if needed
net ads setspn add HTTP/rdpgw.example.com -U Administrator
```

#### Method B: Classic Active Directory / MIT Kerberos (`setspn` / `kadmin`)
For standalone service accounts or MIT Kerberos KDCs:

```bash
# Active Directory (registers SPN on service-account in DC)
setspn -A HTTP/rdpgw.example.com@YOUR.REALM service-account

# MIT Kerberos KDC
kadmin.local -q "addprinc -randkey HTTP/rdpgw.example.com@YOUR.REALM"
```

### 3. Generate Keytab

Once the principal is registered in the realm or domain controller, generate a keytab file:

#### Linux / Samba (`net ads keytab`)
```bash
# Automatically create or update the keytab file and extract registered SPNs from AD
net ads keytab create -P
```

#### Standalone MIT Kerberos (`ktutil`)
```bash
ktutil
addent -password -p HTTP/rdpgw.example.com@YOUR.REALM -k 1 -e aes256-cts-hmac-sha1-96
wkt rdpgw.keytab
quit
```

#### Windows (`ktpass`)
When working in a Windows management environment, use the built-in `ktpass` tool:
```cmd
ktpass /princ HTTP/rdpgw.example.com@YOUR.REALM /pass YourStrongPassword /mapuser YOUR\ServiceAccount /crypto All /ptype KRB5_NT_PRINCIPAL /out C:\path\to\rdpgw.keytab
```

**⚠️ Important Considerations:**
- **AES Encryption (`/crypto All`)**: Ensure modern encryption algorithms (AES128 / AES256) are enabled.
- **Binary Transfer (PowerShell)**: When transferring keytab files from a Windows management station to a Linux gateway or Kubernetes Secret via PowerShell, always read them as raw byte arrays (`[System.IO.File]::ReadAllBytes()`) rather than text strings to prevent UTF-8/Windows-1252 corruption.

#### Keytab Permissions & Secure Storage

Regardless of how the keytab is generated, place the resulting keytab file in a secure location readable only by the gateway user (`rdpgw`):

```bash
sudo mv rdpgw.keytab /etc/keytabs/
sudo chown rdpgw:rdpgw /etc/keytabs/rdpgw.keytab
sudo chmod 600 /etc/keytabs/rdpgw.keytab
```

### 4. Gateway Configuration

Configure RDPGW in `rdpgw.yaml`:

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

#### Stacked Authentication (Kerberos + NTLM Fallback)
RDPGW supports stacking Kerberos and NTLM authentication simultaneously. Non-domain-joined clients seamlessly fall back to NTLM via Samba winbind (`/tmp/rdpgw-auth.sock`), while domain-joined clients use SPNEGO/Kerberos via KDC Proxy.

```yaml
Server:
  Authentication:
    - kerberos
    - ntlm
  AuthSocket: /tmp/rdpgw-auth.sock
Kerberos:
  Keytab: /etc/kerberos/rdpgw.keytab
  Krb5conf: /etc/kerberos/krb5.conf
```

#### Dynamic Keytab Loading & SPN Management
When deploying with Active Directory winbind (`rdpgw-auth-winbind`), RDPGW supports dynamic keytab reloading. The gateway automatically detects updates to the keytab file (e.g. when Samba refreshes the machine account keytab or adds SPNs).

Additionally, the startup script automatically inspects `rdpgw.yaml`'s `GatewayAddress` setting, extracts the gateway FQDN, automatically requests an SPN (`HTTP/<GatewayAddress>`), and registers it both in Active Directory and the keytab. Additional SPNs can be provided via the `KERBEROS_SPNS` environment variable.

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
- UDP and TCP KDCs are both tried, with TCP preferred for large ticket responses (PAC overflow protection)
- KDC host entries without an explicit port default to port 88
- Properly handles framed (4-byte length-prefixed) Kerberos messages over both UDP and TCP

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
