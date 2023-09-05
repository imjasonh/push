#!/usr/bin/env bash

set -e

PRIVATE_KEY=$(cat ./private.pem) \
    GH_CLIENT_ID=$(cat ./gh-client-id) \
    GH_SECRET=$(cat ./gh-secret) \
    KO_DATA_PATH=kodata \
    go run ./
