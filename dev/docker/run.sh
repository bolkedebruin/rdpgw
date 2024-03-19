#!/bin/sh

USER=rdpgw

file="/root/createusers.txt"
if [ -f $file ]
  then
    while IFS=: read -r username password is_sudo
        do
            echo "Username: $username, Password: **** , Sudo: $is_sudo"

            if getent passwd "$username" > /dev/null 2>&1
              then
                echo "User Exists"
              else
                adduser -s /sbin/nologin "$username"
                echo "$username:$password" | chpasswd
            fi
    done <"$file"
fi

cd /opt/rdpgw || exit 1

if [ -n "${RDPGW_SERVER__AUTHENTICATION}" ]; then
  if [ "${RDPGW_SERVER__AUTHENTICATION}" = "local" ]; then
    echo "Starting rdpgw-auth"
    /opt/rdpgw/rdpgw-auth &
  fi
fi

# drop privileges and run the application
su -c /opt/rdpgw/rdpgw ${USER} &
wait
exit $?
