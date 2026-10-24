#!/bin/sh
# Entrypoint for Dockerfile.auth-winbind.
#
# By default winbindd is started inside the container. This requires
# /etc/samba/smb.conf and the domain join state (/var/lib/samba) to be
# provided, e.g. as volumes from a previous "net ads join".
#
# Set RDPGW_AUTH_EXTERNAL_WINBIND=1 to skip starting winbindd and use the
# winbind of a domain-joined host instead (mount its /run/samba and
# /var/lib/samba/winbindd_privileged into the container).
set -e

PRIV_DIR=/var/lib/samba/winbindd_privileged

if [ "${RDPGW_AUTH_EXTERNAL_WINBIND}" != "1" ]; then
  if [ ! -f /etc/samba/smb.conf ]; then
    echo "missing /etc/samba/smb.conf; mount the domain member configuration" >&2
    exit 1
  fi
  mkdir -p /run/samba "${PRIV_DIR}" /var/lib/samba/private /var/lib/samba/lock /var/lib/samba/cores /var/cache/samba /var/log/samba
  chown root:root /var/lib/samba/private
  chmod 0700 /var/lib/samba/private
  chown root:winbindd_priv "${PRIV_DIR}"
  chmod 0750 "${PRIV_DIR}"

  # Create an empty secrets.ldb if missing to satisfy Samba LDB module checks on startup
  if [ ! -f /var/lib/samba/private/secrets.ldb ]; then
    if command -v ldbadd >/dev/null 2>&1; then
      printf "dn: @ATTRIBUTES\n\n" | ldbadd -H /var/lib/samba/private/secrets.ldb >/dev/null 2>&1 || true
    else
      touch /var/lib/samba/private/secrets.ldb 2>/dev/null || true
    fi
  fi

  if ! net ads testjoin >/dev/null 2>&1; then
    if [ -n "${AD_JOIN_USER}" ] && [ -n "${AD_JOIN_PASSWORD}" ]; then
      echo "Joining Active Directory domain as ${AD_JOIN_USER}..."
      net ads join -U "${AD_JOIN_USER}%${AD_JOIN_PASSWORD}"
    else
      echo "--------------------------------------------------------------------------------" >&2
      echo "WARNING: Domain join state not found or invalid, and no credentials provided." >&2
      echo "Please configure AD_JOIN_USER and AD_JOIN_PASSWORD environment variables/secrets," >&2
      echo "OR manually join by executing a shell INSIDE this container and running:" >&2
      echo "    net ads join -U Administrator" >&2
      echo "" >&2
      echo "Examples to access the container:" >&2
      echo "  - Kubernetes: kubectl exec -it <pod-name> -n <namespace> -c rdpgw-auth -- sh" >&2
      echo "  - Docker:     docker exec -it <container-name> sh" >&2
      echo "--------------------------------------------------------------------------------" >&2
      echo "Waiting for domain join..." >&2
      until net ads testjoin >/dev/null 2>&1; do
        sleep 2
      done
      echo "Domain join detected!"
    fi
  fi

  echo "Starting winbindd"
  winbindd -F --no-process-group --debug-stdout -d 2 &
fi

# Wait until winbindd answers before accepting authentication requests.
i=0
until wbinfo -p >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "${i}" -ge 30 ]; then
    echo "winbindd is not responding (wbinfo -p failed)" >&2
    cat /var/log/samba/log.winbindd >&2 2>/dev/null || true
    exit 1
  fi
  sleep 1
done

# Ensure winbindd_privileged Remains accessible to winbindd_priv group after winbindd initializes it.
if [ -d "${PRIV_DIR}" ] && [ "${RDPGW_AUTH_EXTERNAL_WINBIND}" != "1" ]; then
  chgrp winbindd_priv "${PRIV_DIR}"
  chmod 0750 "${PRIV_DIR}"
fi

echo "Starting rdpgw-auth"
exec su-exec rdpgw /opt/rdpgw/rdpgw-auth "$@"
