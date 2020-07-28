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

RUN git clone https://github.com/bolkedebruin/rdpgw.git && \
    cd rdpgw && \
    env GOOS=linux GOARCH=amd64 go build && \
    mkdir -p /opt/rdpgw && \
    mv rdpgw /opt/rdpgw/rdpgw && \
    rm -rf /root/go && \
    rm -rf /rdpgw

COPY rdpgw.yaml /opt/rdpgw/rdpgw.yaml

RUN useradd -m -d /opt/rdpgw -u 1001 -c "rdgw" rdgw && \
    mv server.pem /opt/rdpgw/server.pem && \
    mv key.pem /opt/rdpgw/key.pem && \
    chown -R 1001 /opt/rdpgw && \
    chmod +x /opt/rdpgw/rdpgw

USER 1001
WORKDIR /opt/rdpgw
ENTRYPOINT /opt/rdpgw/rdpgw
