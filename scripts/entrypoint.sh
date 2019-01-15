#!/bin/sh

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/key-rotation/scripts/wait_for.py --deps="config,secret,ldap" && python /opt/key-rotation/scripts/entrypoint.py
else
    python /opt/key-rotation/scripts/wait_for.py --deps="config,secret,ldap" && python /opt/key-rotation/scripts/entrypoint.py
fi
