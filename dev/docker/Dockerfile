# builder stage
FROM golang as builder

# define architectures which could be run rdpgw
RUN dpkgArch="$(dpkg --print-architecture)"; \
    case "$dpkgArch" in \
        arm) ARCH='arm' ;; \
        arm64) ARCH='arm64' ;; \
        amd64) ARCH='amd64' ;; \
        386) ARCH='386' ;; \
        *) echo >&2 "error: unsupported architecture: $apkArch"; exit 1 ;; \
    esac

# certificate
RUN mkdir -p /opt/rdpgw && cd /opt/rdpgw && \
    random=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) && \
    openssl genrsa -des3 -passout pass:$random -out server.pass.key 2048 && \
    openssl rsa -passin pass:$random -in server.pass.key -out key.pem && \
    rm server.pass.key && \
    openssl req -new -sha256 -key key.pem -out server.csr \
    -subj "/C=US/ST=VA/L=SomeCity/O=MyCompany/OU=MyDivision/CN=localhost" && \
    openssl x509 -req -days 365 -in server.csr -signkey key.pem -out server.pem

# add user
RUN adduser --disabled-password --gecos "" --home /opt/rdpgw --uid 1001 rdpgw

# build rdpgw and set rights
RUN git clone https://github.com/bolkedebruin/rdpgw.git /app && \
    cd /app && \
    go mod tidy -compat=1.17 && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -tags '' -ldflags '' -o '/opt/rdpgw/rdpgw' ./cmd/rdpgw && \
    chmod +x /opt/rdpgw/rdpgw && \
    chown -R 1001 /opt/rdpgw

# FROM scratch
# FROM scratch is missing /bin/sh which is sadly needed to start the container.
FROM busybox
# Copy stuff from builder
COPY --from=builder /opt/rdpgw /opt/rdpgw
COPY --from=builder /etc/passwd /etc/passwd
# trust root CA
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
# COPY --from=builder /bin/sh /bin/sh
# COPY rdpgw.yaml
COPY rdpgw.yaml /opt/rdpgw/rdpgw.yaml

USER 1001
WORKDIR /opt/rdpgw
ENTRYPOINT /opt/rdpgw/rdpgw
