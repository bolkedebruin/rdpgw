# Incremental Operational Tracking Plan: `rdpgw-auth` Modernization

This document outlines the shippable, incremental milestones for migrating `rdpgw-auth` from its legacy shell-script wrapper architecture to a fully self-contained, native Go microservice with unified auth pipelines, automated domain joining, process supervision, and modular template-fused PAM generation.

---

## Critical Architecture Note: Winbind Hostname / Machine Account Name Handling
In containerized environments (Kubernetes/Docker), pods receive ephemeral, randomly generated hostnames (e.g., `calacirya-6585fd5899-wsmks`). Samba winbind and Active Directory require a stable, predictable machine account NetBIOS name (`netbios name` in `smb.conf`) so that the computer object in Active Directory and its corresponding Kerberos SPNs remain consistent across pod restarts, rather than using the ephemeral container hostname.
- **Resolution**: `rdpgw-auth` configuration explicitly separates the domain/workgroup name (`netbios: "CORP"`) from the machine computer account name (`netbiosName: "calacirya"`), ensuring the AD machine account name never relies on ephemeral pod hostnames.

---

## Milestone 1: Winbind Configuration Schema & Kerberos Share
### Scope
- Implement Go struct definitions for `WinbindConfig` (including domain controllers list supporting both string lists and detailed host/port objects, and explicit NetBIOS/hostname management).
- Implement `AuthProtocols.Kerberos` (`share: true/false`, `keytabPath`).
- Add legacy backward compatibility mapping specifically for NTLM/Kerberos and `smb.conf` keytab sharing.

### Deliverables
- Updated `cmd/auth/config/configuration.go`.
- Unit tests (`configuration_test.go`) validating NetBIOS resolution and legacy mapping.

---

## Milestone 2: Go-Based Template Engine (`smb.conf` & `krb5.conf`)
### Scope
- Implement file staging in `/tmp/rdpgw/` and mount safety checks (detecting read-only operator mounts).
- Build the Go template engine using embedded templates (`smb.conf.tmpl`, `krb5.conf.tmpl`).
- Implement the strict explode policy (`log.Fatalf`) if operator-mounted `smb.conf` files lack mandatory keytab synchronization directives.

### Deliverables
- Embedded template assets in `cmd/auth/provisioning/templates/` (`smb.conf.tmpl`, `krb5.conf.tmpl`, embedded via `//go:embed templates/*.tmpl`).
- Initialization provisioning logic in `cmd/auth/provisioning/provisioning.go`.

---

## Milestone 3: Domain Join, Process Supervision, and Script Migration
### Scope
- Migrate the shell wrapper logic (`run-auth-winbind.sh`) entirely into Go (`cmd/auth/join.go` and `cmd/auth/supervisor.go`).
- Implement `net ads testjoin` pre-checks, exponential backoff auto-join loop, configurable `JoinTimeout`, and explicit failure explosion (`log.Fatalf`) with clear troubleshooting instructions when unjoined.
- Implement `winbindd` child process supervision (`os/exec`), stdout/stderr redirection, `wbinfo -p` health polling, and graceful signal propagation (`SIGTERM`/`SIGINT`).
- When rewriting keytab directives, update mis-pointed directive lines in place rather than appending duplicates (Milestone 2's append policy leaves both lines on a writable mis-pointed operator file; samba reads them ambiguously).

### Deliverables
- Go-based AD domain join and `winbindd` supervision engine.

---

## Milestone 4: NTLM Backends & Ordering
### Scope
- Implement `AuthProtocols.Ntlm` parsing and execution.
- Support ordered backend execution for NTLM (`winbind`, `users` as alternative/exclusive verifiers).

### Deliverables
- Updated gRPC `NTLM` handler in `cmd/auth/auth.go` supporting ordered NTLM backend execution.

---

## Milestone 5: Modular PAM Stack Generation & Static Users (`users.pwd`)
### Scope
- Implement static YAML users to `pam_pwdfile` integration (`users.pwd` generation under `/tmp/rdpgw/`).
- Deploy `session_manager.sh` alongside `rdpgw-auth` at `/opt/rdpgw/session_manager.sh`.
- Build the dynamic PAM stack generator by fusing ready smaller template blocks (Winbind, LDAP, Unix, Users + OATH) into one unified `/etc/pam.d/rdpgw` file using robust `success=ok default=...` skip logic.

### Deliverables
- PAM template fragment definitions and dynamic fusion engine.
- Session manager script deployment.

---

## Milestone 6: Container Streamlining & Final Release (`rdpgw-auth`)
### Scope
- Update `Dockerfile.auth-winbind` to remove legacy shell scripts (`run-auth-winbind.sh`) and CLI dependencies (`yq-go`).
- Rename binary and container image references to lightweight **`rdpgw-auth`**.
- Update CI/CD build pipelines.
- Verify end-to-end integration on the K3s cluster.

### Deliverables
- Streamlined `Dockerfile.auth-winbind` and updated Kubernetes manifests.
