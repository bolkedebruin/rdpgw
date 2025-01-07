#!/bin/sh

USER=rdpgw

cd /opt/rdpgw || exit 1

/opt/rdpgw/rdpgw-auth -n rdpgw -s /tmp/rdpgw-auth.sock &

# drop privileges and run the application
su -c /opt/rdpgw/rdpgw "${USER}" -- "$@" &
wait
exit $?
