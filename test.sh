#!/bin/sh
docker run --rm \
    -v $(pwd):/app/foundry \
    -u $(id -u):$(id -g) \
    ghcr.io/paradigmxyz/foundry-alphanet@sha256:0b828412ca7c767cd60c1468ae940bed39a8c90d9d7738ce04fde33570f435f8 \
    --foundry-directory /app/foundry \
    --foundry-command "test -vvvv"
