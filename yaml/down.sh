#!/usr/bin/env bash

kubectl delete svc mutation-webhook
kubectl delete deployment mutation-webhook
kubectl delete secret mutation-webhook-certs
kubectl delete pod test-pod
kubectl delete MutatingWebhookConfiguration mutation-webhook-config

