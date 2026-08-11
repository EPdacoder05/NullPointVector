#!/bin/bash

if [ "$1" == "docker" ]; then
    cp .env.docker .env
    echo "Switched to Docker Compose environment (.env.docker → .env)"
elif [ "$1" == "local" ]; then
    cp .env.local .env
    echo "Switched to local environment (.env.local → .env)"
else
    echo "Usage: ./swap_env.sh [docker|local]"
fi