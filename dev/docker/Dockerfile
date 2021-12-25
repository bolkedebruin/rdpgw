FROM debian:buster-slim

RUN apt-get update && \
    apt-get install -y git golang openssl curl && \
    random=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) && \
    openssl genrsa -des3 -passout pass:$random -out server.pass.key 2048 && \
    openssl rsa -passin pass:$random -in server.pass.key -out key.pem && \
    rm server.pass.key && \
    openssl req -new -sha256 -key key.pem -out server.csr \
    -subj "/C=US/ST=VA/L=SomeCity/O=MyCompany/OU=MyDivision/CN=localhost" && \
    openssl x509 -req -days 365 -in server.csr -signkey key.pem -out server.pem

RUN curl -L https://dl.google.com/go/go1.17.5.linux-amd64.tar.gz -o golang.tgz && \
    tar zxvf golang.tgz && rm golang.tgz

RUN git clone https://github.com/bolkedebruin/rdpgw.git && \
    cd rdpgw && \
    env GOOS=linux GOARCH=amd64 GOROOT=/go /go/bin/go mod tidy && \
    env GOOS=linux GOARCH=amd64 GOROOT=/go /go/bin/go build -trimpath -tags '' -ldflags '' -o '/rdpgw/bin/rdpgw' ./cmd/rdpgw && \
    mkdir -p /opt/rdpgw && \
    mv /rdpgw/bin/rdpgw /opt/rdpgw/rdpgw && \
    rm -rf /root/go && \
    rm -rf /rdpgw

RUN rm -rf /go

COPY rdpgw.yaml /opt/rdpgw/rdpgw.yaml

RUN useradd -m -d /opt/rdpgw -u 1001 -c "rdgw" rdgw && \
    mv server.pem /opt/rdpgw/server.pem && \
    mv key.pem /opt/rdpgw/key.pem && \
    chown -R 1001 /opt/rdpgw && \
    chmod +x /opt/rdpgw/rdpgw

USER 1001
WORKDIR /opt/rdpgw
ENTRYPOINT /opt/rdpgw/rdpgw
