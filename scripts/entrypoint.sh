#!/bin/sh

set -e

python3 /app/scripts/wait.py
python3 /app/scripts/entrypoint.py disable-builtin &
python3 /app/scripts/entrypoint.py rotate
