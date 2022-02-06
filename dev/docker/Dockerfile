FROM alpine:latest

RUN apk add --no-cache gcc git make musl-dev go openssl curl

# Configure Go
ENV GOROOT /usr/lib/go
ENV GOPATH /go
ENV PATH /go/bin:$PATH

RUN random=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) && \
    openssl genrsa -des3 -passout pass:$random -out server.pass.key 2048 && \
    openssl rsa -passin pass:$random -in server.pass.key -out key.pem && \
    rm server.pass.key && \
    openssl req -new -sha256 -key key.pem -out server.csr \
    -subj "/C=US/ST=VA/L=SomeCity/O=MyCompany/OU=MyDivision/CN=localhost" && \
    openssl x509 -req -days 365 -in server.csr -signkey key.pem -out server.pem

RUN apkArch="$(apk --print-arch)"; \
    case "$apkArch" in \
        armhf) ARCH='arm' ;; \
        aarch64) ARCH='arm64' ;; \
        x86_64) ARCH='amd64' ;; \
        x86) ARCH='386' ;; \ 
        *) echo >&2 "error: unsupported architecture: $apkArch"; exit 1 ;; \
    esac && \
    git clone https://github.com/bolkedebruin/rdpgw.git && \
    cd rdpgw && \
    go mod tidy && \
    go build -trimpath -tags '' -ldflags '' -o '/rdpgw/bin/rdpgw' ./cmd/rdpgw && \
    mkdir -p /opt/rdpgw && \
    mv /rdpgw/bin/rdpgw /opt/rdpgw/rdpgw && \
    rm -rf /root/go && \
    rm -rf /rdpgw

RUN rm -rf /go

COPY rdpgw.yaml /opt/rdpgw/rdpgw.yaml

RUN adduser --disabled-password --gecos "" -h /opt/rdpgw -u 1001 rdgw && \
    mv server.pem /opt/rdpgw/server.pem && \
    mv key.pem /opt/rdpgw/key.pem && \
    chown -R 1001 /opt/rdpgw && \
    chmod +x /opt/rdpgw/rdpgw

USER 1001
WORKDIR /opt/rdpgw
ENTRYPOINT /opt/rdpgw/rdpgw
