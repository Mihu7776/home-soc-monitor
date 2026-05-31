#!/usr/bin/env sh
set -eu

docker compose --profile traffic up --build iot-normal-traffic
