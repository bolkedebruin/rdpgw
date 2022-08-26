# builder stage
FROM golang as builder

RUN apt-get update && apt-get install -y libpam-dev

# certificate
RUN mkdir -p /opt/rdpgw && cd /opt/rdpgw && \
    random=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) && \
    openssl genrsa -des3 -passout pass:$random -out server.pass.key 2048 && \
    openssl rsa -passin pass:$random -in server.pass.key -out key.pem && \
    rm server.pass.key && \
    openssl req -new -sha256 -key key.pem -out server.csr \
    -subj "/C=US/ST=VA/L=SomeCity/O=MyCompany/OU=MyDivision/CN=rdpgw" && \
    openssl x509 -req -days 365 -in server.csr -signkey key.pem -out server.pem

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
    chmod +x /opt/rdpgw/rdpgw-auth && \
    chmod u+s /opt/rdpgw/rdpgw-auth && \
    chown -R 1001 /opt/rdpgw

FROM scratch 

# make tempdir in case filestore is used
ADD tmp.tar /

COPY --from=builder /opt/rdpgw /opt/rdpgw
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

COPY rdpgw.yaml /opt/rdpgw/rdpgw.yaml

USER 1001
WORKDIR /opt/rdpgw
ENTRYPOINT ["/opt/rdpgw/rdpgw"]
