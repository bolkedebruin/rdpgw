# PAM/Local Authentication

![PAM](images/flow-pam.svg)

RDPGW supports PAM (Pluggable Authentication Modules) for authentication against local accounts, LDAP, Active Directory, and other PAM-supported systems.

## Important Notes

**⚠️ Client Limitation**: The default Windows client `mstsc` does not support basic authentication. Use alternative clients or switch to OpenID Connect, Kerberos, or NTLM authentication.

**⚠️ Container Considerations**: Using PAM for passwd authentication within containers is not recommended. Use OpenID Connect or Kerberos instead. For LDAP/AD authentication, PAM works well in containers.

## Architecture

PAM authentication uses a privilege separation model with the `rdpgw-auth` helper program:

- `rdpgw` - Main gateway (runs as unprivileged user)
- `rdpgw-auth` - Authentication helper (runs as root or setuid)
- Communication via Unix socket

## Configuration

### 1. PAM Service Configuration

Create `/etc/pam.d/rdpgw` for the authentication service:

**Local passwd authentication:**
```plaintext
auth required pam_unix.so
account required pam_unix.so
```

**LDAP authentication:**
```plaintext
auth required pam_ldap.so
account required pam_ldap.so
```

**Active Directory (via Winbind):**
```plaintext
auth sufficient pam_winbind.so
account sufficient pam_winbind.so
```

### 2. Gateway Configuration

```yaml
Server:
  Authentication:
    - local
  AuthSocket: /tmp/rdpgw-auth.sock
  BasicAuthTimeout: 5  # seconds
Caps:
  TokenAuth: false
```

### 3. Start Authentication Helper

Run the `rdpgw-auth` helper program:

```bash
# Basic usage
./rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock

# With custom PAM service name
./rdpgw-auth -n custom-service -s /tmp/rdpgw-auth.sock

# Run as systemd service
systemctl start rdpgw-auth
```

## Authentication Flow

1. Client connects to gateway with username/password
2. Gateway forwards credentials to `rdpgw-auth` via socket
3. `rdpgw-auth` validates credentials using PAM
4. Gateway generates session tokens on successful authentication
5. Client connects directly using authenticated session

## PAM Module Examples

### LDAP Integration

Install and configure LDAP PAM module:

```bash
# Install LDAP PAM module
sudo apt-get install libpam-ldap

# Configure /etc/pam_ldap.conf
host ldap.example.com
base dc=example,dc=com
binddn cn=readonly,dc=example,dc=com
bindpw secret
```

### Active Directory Integration

Configure Winbind PAM module:

```bash
# Install Winbind
sudo apt-get install winbind libpam-winbind

# Configure /etc/samba/smb.conf
[global]
security = ads
realm = EXAMPLE.COM
workgroup = EXAMPLE
```

### Two-Factor Authentication

Integrate with TOTP/HOTP using pam_oath:

```plaintext
auth required pam_oath.so usersfile=/etc/users.oath
auth required pam_unix.so
account required pam_unix.so
```

## Container Deployment

### Option 1: External Helper

Run `rdpgw-auth` on the host and mount socket:

```yaml
# docker-compose.yml
services:
  rdpgw:
    image: rdpgw
    volumes:
      - /tmp/rdpgw-auth.sock:/tmp/rdpgw-auth.sock
```

### Option 2: Privileged Container

Mount PAM configuration and user databases:

```yaml
services:
  rdpgw:
    image: rdpgw
    privileged: true
    volumes:
      - /etc/passwd:/etc/passwd:ro
      - /etc/shadow:/etc/shadow:ro
      - /etc/pam.d:/etc/pam.d:ro
```

## Systemd Service

Create `/etc/systemd/system/rdpgw-auth.service`:

```ini
[Unit]
Description=RDPGW Authentication Helper
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable rdpgw-auth
sudo systemctl start rdpgw-auth
```

## Compatible Clients

Since `mstsc` doesn't support basic authentication, use these alternatives:

### Windows
- **Remote Desktop Connection Manager** (RDCMan)
- **mRemoteNG**
- **Royal TS/TSX**

### Linux
- **Remmina**
- **FreeRDP** (with basic auth support)
- **KRDC**

### macOS
- **Microsoft Remote Desktop** (from App Store)
- **Royal TSX**

## Security Considerations

- Run `rdpgw-auth` with minimal privileges
- Secure the Unix socket with appropriate permissions
- Use strong PAM configurations (account lockout, password complexity)
- Enable logging for authentication events
- Consider rate limiting for brute force protection
- Use encrypted connections (TLS) for the gateway

## Troubleshooting

### Common Issues

1. **Socket Permission Denied**: Check socket permissions and ownership
2. **PAM Authentication Failed**: Verify PAM configuration and user credentials
3. **Helper Not Running**: Ensure `rdpgw-auth` is running and accessible

### Debug Commands

```bash
# Test PAM configuration
pamtester rdpgw username authenticate

# Check socket
ls -la /tmp/rdpgw-auth.sock

# Verify helper process
ps aux | grep rdpgw-auth

# Test authentication manually
echo "username:password" | nc -U /tmp/rdpgw-auth.sock
```

### Log Analysis

Enable PAM logging in `/etc/rsyslog.conf`:

```plaintext
auth,authpriv.*                 /var/log/auth.log
```

Monitor authentication attempts:

```bash
tail -f /var/log/auth.log | grep rdpgw
```
