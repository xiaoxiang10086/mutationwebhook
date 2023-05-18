#!/usr/bin/env bash

kubectl apply -f test-pod.yaml
kubectl logs test-pod -c injected-container