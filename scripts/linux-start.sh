#!/usr/bin/env sh
set -eu

docker compose up --build -d home-soc-monitor

printf '\nHome SOC Monitor is starting.\n'
printf 'Dashboard: http://localhost:%s\n' "${APP_PORT:-8080}"
printf 'Health:    http://localhost:%s/actuator/health\n\n' "${APP_PORT:-8080}"

docker compose ps
