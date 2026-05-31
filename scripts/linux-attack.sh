#!/usr/bin/env sh
set -eu

docker compose --profile attack up --build attacker
