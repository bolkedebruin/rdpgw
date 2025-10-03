# builder stage
FROM golang:1.24-alpine as builder

# Install CA certificates explicitly in builder
RUN apk --no-cache add git gcc musl-dev linux-pam-dev openssl

# add user
RUN adduser --disabled-password --gecos "" --home /opt/rdpgw --uid 1001 rdpgw

# certificate generation
RUN mkdir -p /opt/rdpgw && cd /opt/rdpgw && \
    random=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) && \
    openssl genrsa -des3 -passout pass:$random -out server.pass.key 2048 && \
    openssl rsa -passin pass:$random -in server.pass.key -out key.pem && \
    rm server.pass.key && \
    openssl req -new -sha256 -key key.pem -out server.csr \
    -subj "/C=US/ST=VA/L=SomeCity/O=MyCompany/OU=MyDivision/CN=rdpgw" && \
    openssl x509 -req -days 365 -in server.csr -signkey key.pem -out server.pem

# build rdpgw and set rights
ARG CACHEBUST
RUN git clone https://github.com/bolkedebruin/rdpgw.git /app && \
    cd /app && \
    go mod tidy -compat=1.19 && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -tags '' -ldflags '' -o '/opt/rdpgw/rdpgw' ./cmd/rdpgw && \
    CGO_ENABLED=1 GOOS=linux go build -trimpath -tags '' -ldflags '' -o '/opt/rdpgw/rdpgw-auth' ./cmd/auth && \
    chmod +x /opt/rdpgw/rdpgw && \
    chmod +x /opt/rdpgw/rdpgw-auth && \
    chmod u+s /opt/rdpgw/rdpgw-auth

FROM alpine:latest
# Install CA certificates in final stage
RUN apk --no-cache add linux-pam musl tzdata ca-certificates && update-ca-certificates

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

USER 0
WORKDIR /opt/rdpgw
ENTRYPOINT ["/bin/sh", "/run.sh"]
