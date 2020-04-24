#!/bin/sh

set -e

python /app/scripts/wait.py
python /app/scripts/entrypoint.py disable-builtin &
python /app/scripts/entrypoint.py rotate
