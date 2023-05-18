#!/usr/bin/env bash

openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout webhook.key -out webhook.crt \
    -subj "/CN=mutation-webhook.default.svc" \
    -reqexts SAN -extensions SAN \
    -config <(cat /etc/ssl/openssl.cnf \
        <(printf "[SAN]\nsubjectAltName=DNS:mutation-webhook.default.svc"))

cat webhook.crt | base64 -w0 >> base64-webhook.crt
cat webhook.key | base64 -w0 >> base64-webhook.key
