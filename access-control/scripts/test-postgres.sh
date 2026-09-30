#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
./scripts/init-env.sh
docker compose up -d --wait db
set -a
. ./.env
set +a
# Tests create random schemas and delete only those schemas on completion.
export TEST_DATABASE_URL="postgres://postgres:$POSTGRES_PASSWORD@127.0.0.1:$POSTGRES_PORT/access_control?sslmode=disable"
exec go test -race -count=1 ./...
