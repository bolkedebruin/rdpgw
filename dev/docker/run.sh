#!/bin/sh
cd /opt/rdpgw || exit 1

if ! [ -e /opt/rdpgw/rdpgw.yaml ]; then
  cp /opt/rdpgw/rdpgw.yaml.default /opt/rdpgw/rdpgw.yaml
fi

/opt/rdpgw/rdpgw-auth &
/opt/rdpgw/rdpgw &
wait
exit $?
