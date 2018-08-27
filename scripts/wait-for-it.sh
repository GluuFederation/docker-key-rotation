#!/bin/sh

set -e

if [ -f /etc/redhat-release ]; then
    source scl_source enable python27 && python /opt/key-rotation/scripts/wait_for_it.py "$@"
else
    python /opt/key-rotation/scripts/wait_for_it.py "$@"
fi
