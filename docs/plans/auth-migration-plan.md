# Comprehensive Implementation Plan: Unified Auth Pipelines, Go-Based Initialization, and Stateful PAM Branching for `rdpgw-auth`

This document defines the complete architectural design, configuration schema, Go-based initialization workflow, Active Directory automation, and stateful PAM branching for `rdpgw-auth`. It serves as the definitive reference and tracking document for the migration.

---

## 1. Architectural Vision & Scope

### 1.1 Problem Statement
1. **Android & Mobile Client Compatibility**: Modern Microsoft Remote Desktop clients on Android and iOS require HTTP Basic authentication challenges (`WWW-Authenticate: Basic`) alongside NTLM and Negotiate to display credential dialogs and connect to the RD Gateway.
2. **Fragile Shell Wrappers**: Container startup currently relies on complex shell scripts (`run-auth-winbind.sh`), `yq-go`, and hand-crafted static PAM files. These scripts are brittle, cannot express dynamic conditional branching between authentication backends, and complicate container lifecycle management.
3. **Alpine PAM Account Phase Limitation**: Alpine Linux uses `musl` libc, which lacks glibc NSS support. When authenticating Active Directory domain users, standard PAM configurations fail during the `account` phase (`t.AcctMgmt(0)`) because local user lookups (`getpwnam`) fail against `/etc/passwd`.
4. **Container Hostname / NetBIOS Machine Account Name**: In containerized environments (Kubernetes/Docker), pods receive ephemeral, randomly generated hostnames (e.g., `calacirya-6585fd5899-wsmks`). Samba winbind and Active Directory require a stable, predictable machine account NetBIOS name (`netbios name` in `smb.conf`) so that the computer object in Active Directory and its corresponding Kerberos SPNs remain consistent across pod restarts, rather than using the ephemeral container hostname.

### 1.2 Solution Architecture
- **Unified Configuration Schema**: Backward-compatible YAML configuration supporting multiple identity backends (`Winbind`, `Ldap`, `Users`, `Unix`, `Oath`) and protocol frontends (`Kerberos`, `Ntlm`, `Basic`).
- **Native Go Initializer**: Completely replaces shell wrapper scripts. The compiled Go binary renders configuration templates (`smb.conf`, `krb5.conf`, PAM stacks), enforces keytab synchronization based on protocol configurations, manages automated domain joins with exponential backoff, and supervises `winbindd` as a child process.
- **Stateful PAM Branching (`pam_exec`)**: Uses a lightweight session tracker (`session_manager.sh`, installed alongside `rdpgw-auth`) combined with PAM control-flag jumps (`[success=ok default=...]`) to guarantee that the `account` verification phase deterministically matches whichever backend succeeded during the `auth` phase.

---

## 2. Complete Configuration Reference (`rdpgw-auth.yaml`)

```yaml
# ==========================================
# RDPGW-AUTH ADVANCED CONFIGURATION
# ==========================================

# 1. Active Directory Integration via Winbind (Single instance)
Winbind:
  domain: "example.corp.local"          # FQDN of the domain (DNS Realm)
  workgroup: "CORP"                     # NetBIOS Domain Name / Workgroup (Pre-Windows 2000 domain)
  hostname: "rdpgw-auth"                # Machine Computer Name in AD (sets 'netbios name' in smb.conf)
  ntlmAuthPath: "/usr/bin/ntlm_auth"    # Path to ntlm_auth helper (default: /usr/bin/ntlm_auth)
  timeout: 10                           # Request timeout in seconds
  autoJoin: true                        # When true, automatically attempt domain join if unjoined; when false, wait and report instructions
  joinTimeout: 10                       # Max minutes to attempt automatic AD domain join or wait for manual join (default: 10)
  stripDomain: false                    # Strip domain prefix before passing to helper
  separator: "\\"                       # Domain/username separator (default: \\, properly escaped)
  domainControllers:                    # Supports both simple string list (default ports) or detailed objects
    - "dc1.example.corp.local"
    - host: "dc2.example.corp.local"
      port: 88
      adminPort: 749

# 2. LDAP Directories (Multiple allowed)
Ldap:
  - name: "corp-ldap"
    host: "ldap.example.com"
    port: 636
    tls: true
    base: "dc=example,dc=com"
    binddn: "cn=readonly,dc=example,dc=com"
    bindpw: "secret"

# 3. Local In-YAML Static Users (For break-glass or simple deployments)
Users:
  - Username: "alice"
    Password: "secure_password_1"
  - Username: "admin"
    Password: "admin_secure_password"

# 4. Multiple Named OATH Policies (TOTP/HOTP 2FA)
Oath:
  - name: "default-totp"
    usersfile: "/etc/users.oath"
    window: 30                          # Time step window
  - name: "strict-yubikey"
    usersfile: "/etc/yubikey.oath"

# 6. Protocol Frontends & Authentication Pipelines
AuthProtocols:
  # Kerberos Protocol: Controls machine keytab synchronization with rdpgw gateway
  Kerberos:
    share: true                         # When true, injects keytab sync directives into smb.conf
    keytabPath: "/var/lib/samba/rdpgw.keytab" # Path where the shared keytab is stored
    spns:                               # SPNs to register in AD and add to the shared keytab
      - "HTTP/rdpgw.example.corp.local" # (only meaningful when share: true)

  # NTLM Protocol: Ordered list of NT-hash capable backends (fully sortable/combinable)
  Ntlm:
    enabled: true
    backends:
      - "winbind"
      - "users"                         # Can combine/sort multiple NTLM backends freely

  # Basic / Password Protocol: Full rich PAM stack with multiple backends and OATH 2FA linking
  Basic:
    enabled: true
    stack:
      - backend: "winbind"
        oath: "default-totp"            # Optional: attach 2FA to Winbind auth

      - backend: "ldap"
        name: "corp-ldap"               # References Ldap block named "corp-ldap"
        oath: "strict-yubikey"

      - backend: "unix"                 # Local system users /etc/shadow
        # no oath

      - backend: "users"                # Local YAML static users
        oath: "default-totp"
```

---

## 3. Go Struct Definitions & Backward Compatibility Mapper

### 3.1 Go Structs (`cmd/auth/config/configuration.go`)
```go
package config

import (
    "strings"
    "gopkg.in/yaml.v3"
)

type Configuration struct {
    Winbind       *WinbindConfig       `koanf:"winbind"`
    Ldap          []LdapConfig         `koanf:"ldap"`
    Users         []UserConfig         `koanf:"users"`
    Unix          *UnixConfig          `koanf:"unix"`
    Oath          []OathConfig         `koanf:"oath"`
    AuthProtocols *AuthProtocolsConfig `koanf:"authprotocols"`

    // Legacy fields for backward compatibility
    Ntlm          *LegacyNtlmConfig    `koanf:"ntlm"`
}

type WinbindConfig struct {
    Domain             string               `koanf:"domain"`
    Workgroup          string               `koanf:"workgroup"`
    Hostname           string               `koanf:"hostname"`
    NtlmAuthPath       string               `koanf:"ntlm auth path"`
    Timeout            int                  `koanf:"timeout"`
    AutoJoin           bool                 `koanf:"autojoin"`
    JoinTimeout        int                  `koanf:"jointimeout"`
    StripDomain        bool                 `koanf:"stripdomain"`
    Separator          string               `koanf:"separator"`
    DomainControllers  []DomainController   `koanf:"domaincontrollers"`
}

// SPNs live under AuthProtocols.Kerberos: registering them is only
// meaningful when the machine keytab is shared with the gateway.
type KerberosProtocolConfig struct {
    Share      bool     `koanf:"share"`
    KeytabPath string   `koanf:"keytabpath"`
    Spns       []string `koanf:"spns"`
}

type DomainController struct {
    Host      string `koanf:"host"`
    Port      int    `koanf:"port"`
    AdminPort int    `koanf:"adminport"`
}

// Custom unmarshaler to support both simple string list and detailed objects for domainControllers
type FlexibleDomainController struct {
    DomainController
}

func (f *FlexibleDomainController) UnmarshalYAML(value *yaml.Node) error {
    var s string
    if err := value.Decode(&s); err == nil {
        f.Host = s
        f.Port = 88
        f.AdminPort = 749
        return nil
    }
    return value.Decode(&f.DomainController)
}

// ... other struct definitions (LdapConfig, UserConfig, UnixConfig, OathConfig, AuthProtocolsConfig)
```

### 3.2 NetBIOS Auto-Derivation & Legacy Mapping
- If `Winbind.Netbios` is empty and `Winbind.Domain` is set, auto-derive the NetBIOS name:
  ```go
  if c.Winbind != nil && c.Winbind.Netbios == "" && c.Winbind.Domain != "" {
      parts := strings.Split(c.Winbind.Domain, ".")
      c.Winbind.Netbios = strings.ToUpper(parts[0])
  }
  ```
- If `AuthProtocols` is omitted:
  1. If legacy `Ntlm.Backend == "winbind"` or `Winbind` block exists:
     - Map `AuthProtocols.Kerberos` -> `share: true`, `keytabPath: "/var/lib/samba/rdpgw.keytab"`.
     - Map `AuthProtocols.Ntlm` -> `enabled: true`, `backends: ["winbind"]`.
     - Map `AuthProtocols.Basic` -> `enabled: true`, `stack: [{backend: "unix"}]` (default legacy Basic auth maps strictly to local unix PAM profile).
  2. If `Users` list exists and `Ntlm.Backend` is file/empty:
     - Map `AuthProtocols.Ntlm` -> `enabled: true`, `backends: ["users"]`.
     - Map `AuthProtocols.Basic` -> `enabled: true`, `stack: [{backend: "unix"}]`.
  3. If neither is specified (default Basic auth fallback):
     - Map `AuthProtocols.Basic` -> `enabled: true`, `stack: [{backend: "unix"}]` (matching Alpine's default `base-auth` / `base-account`).

---

## 4. Go Initialization Engine & Templates

### 4.1 Mount Safety & Staging
- **Working Staging Directory**: `/tmp/rdpgw/`.
- **Target Files**: `/etc/samba/smb.conf`, `/etc/krb5.conf`, `/etc/pam.d/rdpgw`.
- **Mount Detection Algorithm**:
  1. Inspect target file via `os.Stat`.
  2. Attempt opening with `os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0)`.
  3. If open fails due to read-only filesystem (`syscall.EROFS`), the file is an operator-mounted read-only volume.
  4. If operator-mounted, do not overwrite or unmount.

### 4.2 Keytab Synchronization Enforcement & Explode Policy
Kerberos SPNEGO in `rdpgw` requires that Samba's machine credentials sync automatically to the shared keytab. When `AuthProtocols.Kerberos.Share` is `true`:
- Default Keytab path: `/var/lib/samba/rdpgw.keytab` (or custom `AuthProtocols.Kerberos.KeytabPath`).
- Required directives in `[global]` section:
  ```ini
  dedicated keytab file = <KeytabPath>
  sync machine password to keytab = "<KeytabPath>:sync_spns:sync_kvno:machine_password"
  ```
- **Explode Policy**:
  - If `smb.conf` is dynamically generated: Go renders the directives directly into the template.
  - If `smb.conf` is operator-mounted: Go inspects the file content. If `dedicated keytab file`, `sync machine password to keytab`, or `winbind separator = \\` are missing, or if they point to different files than configured:
    - Go attempts to append/fix them if writable.
    - If the file is mounted read-only and missing these directives or misconfigured, **`auth` explodes and terminates immediately (`log.Fatalf`)** with an actionable fatal error containing instructions on how to configure or call services.

### 4.3 Embedded Templates (`cmd/auth/templates/`)
Using Go `embed` (`//go:embed`):
1. **`smb.conf.tmpl`**:
   ```ini
   [global]
       security = ads
       realm = {{ .Realm }}
       workgroup = {{ .Workgroup }}
       netbios name = {{ .NetbiosName }}
       winbind use default domain = no
       winbind separator = {{ .Separator }}
       idmap config * : backend = tdb
       idmap config * : range = 3000-7999
       idmap config {{ .Workgroup }} : backend = rid
       idmap config {{ .Workgroup }} : range = 10000-999999
       kerberos method = secrets and keytab
   {{- if .KerberosShare }}
       dedicated keytab file = {{ .KeytabPath }}
       sync machine password to keytab = "{{ .KeytabPath }}:sync_spns:sync_kvno:machine_password"
   {{- end }}
       winbind refresh tickets = yes
   ```
2. **`krb5.conf.tmpl`**:
   ```ini
   [libdefaults]
       default_realm = {{ .Realm }}
       dns_lookup_realm = true
       dns_lookup_kdc = true

   [realms]
       {{ .Realm }} = {
   {{- range .DomainControllers }}
           kdc = {{ .Host }}:{{ .Port }}
           admin_server = {{ .Host }}:{{ .AdminPort }}
   {{- end }}
       }

   [domain_realm]
       .{{ .DomainLower }} = {{ .Realm }}
       {{ .DomainLower }} = {{ .Realm }}
   ```
3. **`pam.tmpl`**: Dynamic template rendering the stateful `pam_exec` stack using intelligent `success=ok default=...` skip logic.

### 4.4 Static YAML Users to PAM Integration (`users` backend)
For the `users` backend (static YAML credentials) to work within the PAM `Basic` stack, the Go initializer performs the following:
- **Generation**: Go reads the `Users` list from `rdpgw-auth.yaml`.
- **Formatting**: It generates a standard `pam_pwdfile` compatible file at `/tmp/rdpgw/users.pwd` in the format `username:encrypted_password` (using `crypt(3)`).
- **PAM Integration**: The dynamically generated PAM stack includes:
  ```plaintext
  auth sufficient pam_pwdfile.so /tmp/rdpgw/users.pwd
  ```
- **Lifecycle**: This file is regenerated on every startup to ensure the PAM stack always reflects the current `Users` configuration.

---

## 5. Active Directory Automation & Subprocess Supervision

### 5.1 Automated Domain Join (`cmd/auth/join.go`)
- **Conditional Check**: Domain join logic is executed **only if the Winbind backend is compiled/configured**. If Winbind is absent, join logic is entirely bypassed.
- **Join Test (`net ads testjoin`)**:
  - Execute `net ads testjoin`. If return code `0`, domain join is active; skip join sequence.
- **Auto-Join Logic (`AutoJoin: true` vs `false`)**:
  - **If `AutoJoin: true`**:
    - Check environment variables `AD_JOIN_USER` and `AD_JOIN_PASSWORD`.
    - If present: Start retry loop with configurable `JoinTimeout` (default 10 minutes) and exponential backoff (2s up to 30s).
    - If credentials are absent or join fails after timeout: **Explode and terminate immediately (`log.Fatalf`)** with an error message detailing how to provide credentials or join manually.
  - **If `AutoJoin: false`**:
    - Do not attempt automatic join. Enter a wait loop lasting `JoinTimeout` minutes, reporting as the first log message clear instructions on how to perform that manual join (e.g., `net ads join -U Administrator`), and clarifying that the daemon is waiting for it. If timeout expires without join, **explode (`log.Fatalf`)**.

### 5.2 Subprocess Supervision (`cmd/auth/supervisor.go`)
- Executed via an operator-configurable command / arguments (e.g. supporting custom debug levels like `-d 5` instead of hardcoded `-d 2`).
- Default command: `winbindd -F --no-process-group --debug-stdout -d 2`.
- Pipe stdout/stderr to Go logger with prefix `[winbindd]`.
- Health check: Poll `wbinfo -p` until `winbindd` responds before opening gRPC socket.
- Signal Propagation: Intercept `SIGTERM` and `SIGINT` in Go, gracefully terminate `winbindd`, remove socket, and exit cleanly.

---

## 6. Stateful PAM Branching via `pam_exec` & Skip Logic

### 6.1 Session Manager Script Installation & Location
- The script `session_manager.sh` is installed **alongside `auth` binary** at `/opt/rdpgw/session_manager.sh` (mode `0755`).
- Runtime session files are stored under `/tmp/pam/sessions/` (mode `0700`).

```sh
#!/bin/sh
BASE_DIR="/tmp/pam/sessions"

SAFE_USER=$(echo "$PAM_USER" | tr '/' '_')
TARGET_FILE="${BASE_DIR}/${SAFE_USER}"

case "$1" in
    "create")
        mkdir -p "$BASE_DIR"
        chmod 0700 "$BASE_DIR"
        echo "$2" > "$TARGET_FILE"
        ;;
    "check")
        if [ -f "$TARGET_FILE" ] && [ "$(cat "$TARGET_FILE")" = "$2" ]; then
            exit 0
        else
            exit 1
        fi
        ;;
    "cleanup")
        if [ -n "$SAFE_USER" ]; then
            rm -f "$TARGET_FILE"
        fi
        ;;
    *)
        exit 1
        ;;
esac
```

### 6.2 Dynamic PAM Stack Layout with Skip Logic (`/etc/pam.d/rdpgw`)
To avoid arithmetic guesswork when calculating line jumps across variable-length backend blocks, the PAM generator uses robust control flow:
`success=ok default=N` (where `N` matches the exact number of lines to skip for that backend block).

```plaintext
# =========================================================
# DYNAMIC STACKED PAM CONFIGURATION FOR RDPGW
# =========================================================

# --- AUTH PHASE ---
# Example: Winbind block with OATH (2 auth modules + 1 session create = 3 lines block)
auth [success=ok default=2]       pam_oath.so usersfile=/etc/users.oath
auth [success=ok default=1]       pam_winbind.so krb5_auth
auth [success=done]               pam_exec.so /opt/rdpgw/session_manager.sh create winbind

# Example: Unix block (1 auth module + 1 session create = 2 lines block)
auth [success=ok default=1]       pam_unix.so nullok try_first_pass
auth [success=done]               pam_exec.so /opt/rdpgw/session_manager.sh create unix

# Fallback Deny
auth required                     pam_deny.so

# --- ACCOUNT PHASE ---
account [success=2 default=ignore] pam_exec.so quiet /opt/rdpgw/session_manager.sh check winbind
account [success=1 user_unknown=die default=ignore] pam_winbind.so
account required                                       pam_deny.so
account [success=done]                                 pam_exec.so /opt/rdpgw/session_manager.sh cleanup

account [success=2 default=ignore] pam_exec.so quiet /opt/rdpgw/session_manager.sh check unix
account [success=1 default=ignore]                  pam_unix.so
account required                                       pam_deny.so
account [success=done]                                 pam_exec.so /opt/rdpgw/session_manager.sh cleanup

account [success=done]                                 pam_permit.so
```

---

## 7. Container Streamlining & Deployment (`rdpgw-auth`)

### 7.1 Dockerfile Changes (`dev/docker/Dockerfile.auth-winbind`)
- Rename image / binary references to clean, lightweight **`rdpgw-auth`**.
- Remove external shell script `run-auth-winbind.sh` and CLI utility `yq-go`.
- Copy `session_manager.sh` to `/opt/rdpgw/session_manager.sh`.
- Set container entrypoint directly to the compiled Go binary:
  ```dockerfile
  COPY cmd/auth/scripts/session_manager.sh /opt/rdpgw/session_manager.sh
  RUN chmod 0755 /opt/rdpgw/session_manager.sh
  ENTRYPOINT ["/opt/rdpgw/rdpgw-auth"]
  ```

### 7.2 Verification Checklist
1. Build `rdpgw-auth` container image locally.
2. Deploy updated container and manifests to namespace on K3s cluster.
3. Verify logs via SSH:
   - Config file rendering in `/tmp/rdpgw/`.
   - `net ads testjoin` execution and `winbindd` process supervision with custom verbosity.
   - Keytab sync line verification in `smb.conf` (or explode check on read-only mount).
   - Successful authentication from Android RD Client (Basic auth) and Windows `mstsc` (NTLM & Kerberos).
