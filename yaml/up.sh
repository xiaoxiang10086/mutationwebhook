#!/usr/bin/env bash

kubectl apply -f mutation-webhook-certs.yaml
kubectl apply -f mutation-webhook.yaml
kubectl apply -f mutation-webhook-config.yaml
