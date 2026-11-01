# Go version must satisfy the "go" directive in go.mod
FROM mcr.microsoft.com/devcontainers/go:1.25

# cmd/auth links against PAM via cgo, so its headers and a C toolchain are required
RUN apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y --no-install-recommends libpam0g-dev build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
