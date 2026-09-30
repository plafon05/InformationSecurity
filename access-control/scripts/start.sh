#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
./scripts/init-env.sh
docker compose up -d --wait db
set -a
. ./.env
set +a
exec go run ./cmd/access-control "$@"
