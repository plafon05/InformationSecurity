#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -e .env ]; then
  printf '%s\n' '.env уже существует; настройки сохранены.'
  exit 0
fi
umask 077
admin_secret=$(openssl rand -hex 32)
app_secret=$(openssl rand -hex 32)
# noclobber prevents overwriting a concurrently created configuration.
set -C
cat > .env <<ENV
POSTGRES_PASSWORD=$admin_secret
APP_DB_PASSWORD=$app_secret
POSTGRES_PORT=55432
DATABASE_URL=postgres://access_control:$app_secret@127.0.0.1:55432/access_control?sslmode=disable
ENV
printf '%s\n' 'Создан .env со случайными паролями базы данных.'
