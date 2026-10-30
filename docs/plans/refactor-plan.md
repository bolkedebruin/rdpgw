# Refactor Plan: Open Discussion Items

This document collects refactoring candidates that are **not** part of the
`rdpgw-auth` migration milestones tracked in `auth-operations-plan.md`
and `auth-migration-plan.md`. Items here are open for discussion: they
carry options and tradeoffs instead of decisions, and each one becomes a
tracked milestone only after it is agreed upon.

---

## 1. Module Path Rename & Fork Provenance

### Current situation
The repository is a fork chain (`bolkedebruin/rdpgw` → `liveinvalley/rdpgw`
→ fork), but `go.mod` still declares `module github.com/bolkedebruin/rdpgw`.
Every intra-repo import (`github.com/bolkedebruin/rdpgw/cmd/...`) therefore
*visually* references the original upstream repository although, in Go
module semantics, import paths resolve locally against the declaration in
`go.mod`: nothing is ever fetched from the upstream URL at build time.

### Options
1. **Keep the upstream path** (current state).
   - Pros: zero churn; identical to how every other fork of this project
     is structured; diff-rebase friendliness against upstream stays
     maximal ([no import-path conflicts in merges]).
   - Cons: misleading provenance — readers of the source tree believe the
     code comes from `bolkedebruin`; if the fork is ever consumed as a
     library (`go get <fork>/...`) it cannot be, because Go refuses to
     resolve a forked module whose declared path points elsewhere.
2. **Rename to the direct-fork path, e.g. `github.com/liveinvalley/rdpgw`.**
   - Pros: honest provenance for the tree shape that actually exists.
   - Cons: still not "your" namespace; same rebase friction as option 3.
3. **Rename to the final fork destination** (e.g. `github.com/<owner>/rdpgw`).
   - Status: **open — currently not desired** by the maintainer for this
     proposal; recorded here because it is the long-term end state most
     Go forks converge to once the fork stops tracking upstream.

### Effort (any rename variant)
Mechanical and atomic: one line in `go.mod`, rewrite of all intra-repo
import statements, `gofmt`, then the two established verification paths
(Windows unit tests; WSL2 full `CGO_ENABLED=1` Linux build).
Stray debug artifacts (`cmd/auth/config/__debug_bin*.exe*`) should be
removed in the same commit.

### Open questions
- Which target path (if any)?
- Do we still intend to rebase on top of upstream `bolkedebruin/rdpgw`
  follow-up commits? (Strongest argument for keeping option 1.)

---

## 2. Unify the Gateway Config Loading With The Auth One

### Current situation
- `cmd/auth/config` was migrated to `sigs.k8s.io/yaml` (case-insensitive,
  k8s-maintained) after `koanf` fought back on custom decoders.
- The gateway (`cmd/rdpgw/config`, `cmd/rdpgw/rdp`) still uses `koanf`
  (v2 + parsers/yaml + providers/file/env/confmap).

### Options
1. Leave the gateway on koanf: two config idioms coexist, each fit for its
   surface (gateway env overlay via koanf's env provider is used today).
2. Port the gateway to `sigs.k8s.io/yaml` as well, dropping koanf entirely:
   one direct dependency less on the total tree, case-insensitive YAML
   everywhere (matches the k8s-flavored consumer base), but the env-overlay
   behavior (`RDPGW_...` variables) and RDP file parsing must be
   reimplemented/hand-checked as part of the switch.

### Open questions
- Is the gateway's env-overlay feature relied upon in deployments
  (Kubernetes manifests under `dev/docker`)?

---

## 3. Drop The Compile-Time Compatibility Mirror

### Current situation
`cmd/auth/ntlm/backendcompat_test.go` mirrors `newNtlmBackend` from
`cmd/auth/auth.go` so the modern Configuration surface is type-checked on
any OS (cmd/auth itself stays Linux-buildable-only due to PAM). The
mirror must be manually kept in sync with `auth.go` after each change.

### Options
1. Keep it: catches field-rename drift early on every platform.
2. Replace with a build-tag-protected thin `newNtlmBackend` extracted into
   a Linux/cgo-free helper package that `auth.go` imports directly — no
   mirror at all, single source of truth (needs a small package split).

### Open questions
- Is the mirror cost acceptable, or should we invest in option 2?

---

## 4. Repository Hygiene

### Current situation
- `cmd/auth/config/__debug_bin*.exe*` scratch artifacts appear whenever a
  debugger session ends uncleanly; currently one file is stuck held by a
  live process.
- `gofmt -l` still lists a handful of pre-existing files
  (`cmd/auth/database/*`, `cmd/auth/peercred_linux.go`,
  `cmd/auth/ntlm/ntlm_test.go`) that predate the current refactor wave.

### Proposal
Add a `.gitignore` entry for `__debug_bin*`, gofmt the legacy files in a
formatting-only commit, and note the convention in the contributing docs.

### Open questions
- None recorded yet.
