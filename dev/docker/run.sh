#!/bin/sh
set -e

cd /opt/rdpgw

# Generate an ephemeral self-signed cert at first start when one is not
# already mounted/present at the configured path. Each container instance
# gets its own key; nothing is baked into the image. This is intended for
# the dev compose stack -- production deployments should mount a real
# certificate, or set Tls=auto so rdpgw obtains one from Let's Encrypt.
CERT="${RDPGW_SERVER__CERT_FILE:-/opt/rdpgw/server.pem}"
KEY="${RDPGW_SERVER__KEY_FILE:-/opt/rdpgw/key.pem}"
if [ ! -f "${CERT}" ] && [ ! -f "${KEY}" ]; then
  echo "Generating ephemeral self-signed cert at ${CERT} / ${KEY} (dev only)"
  openssl req -x509 -newkey rsa:2048 -keyout "${KEY}" -out "${CERT}" \
    -sha256 -days 365 -nodes \
    -subj "/CN=rdpgw-ephemeral"
fi

if [ "${RDPGW_SERVER__AUTHENTICATION}" = "local" ]; then
  echo "Starting rdpgw-auth"
  /opt/rdpgw/rdpgw-auth &
fi

exec /opt/rdpgw/rdpgw "$@"
