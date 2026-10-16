#!/bin/sh
set -eu
export APP_KEY="$(cat /run/secrets/app_key)"
export DB_PASSWORD="$(cat /run/secrets/database_password)"
exec "$@"
