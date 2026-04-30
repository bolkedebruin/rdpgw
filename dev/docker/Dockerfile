# builder stage
FROM golang:1.24-alpine as builder

# Install CA certificates explicitly in builder
RUN apk --no-cache add git gcc musl-dev linux-pam-dev

# add user
RUN adduser --disabled-password --gecos "" --home /opt/rdpgw --uid 1001 rdpgw

# build rdpgw and set rights
ARG CACHEBUST
RUN git clone https://github.com/bolkedebruin/rdpgw.git /app && \
    cd /app && \
    go mod tidy -compat=1.19 && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -tags '' -ldflags '' -o '/opt/rdpgw/rdpgw' ./cmd/rdpgw && \
    CGO_ENABLED=1 GOOS=linux go build -trimpath -tags '' -ldflags '' -o '/opt/rdpgw/rdpgw-auth' ./cmd/auth && \
    chmod +x /opt/rdpgw/rdpgw && \
    chmod +x /opt/rdpgw/rdpgw-auth

FROM alpine:latest
# Install CA certificates and (for the dev compose) openssl so the
# entrypoint can mint an ephemeral self-signed cert at startup. No cert
# is baked into the image, so each container instance gets its own key.
RUN apk --no-cache add linux-pam musl tzdata ca-certificates openssl && update-ca-certificates

# make tempdir in case filestore is used
ADD tmp.tar /
COPY --chown=0 rdpgw-pam /etc/pam.d/rdpgw

USER 1001
COPY --chown=1001 run.sh run.sh
COPY --chown=1001 --from=builder /opt/rdpgw /opt/rdpgw
COPY --chown=1001 --from=builder /etc/passwd /etc/passwd

# Copy templates directory
COPY --from=builder /app/cmd/rdpgw/templates /opt/rdpgw/templates

# Copy assets directory from the app source
COPY --chown=1001 --from=builder /app/assets /opt/rdpgw/assets

WORKDIR /opt/rdpgw
ENTRYPOINT ["/bin/sh", "/run.sh"]
