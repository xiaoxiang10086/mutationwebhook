#!/usr/bin/env bash

#kubectl get deployments
kubectl get pods
kubectl get pods -l app=mutation-webhook -o name
#kubectl get deployments
#kubectl describe deployment mutation-webhook
#kubectl describe replicaset mutation-webhook-585c789755
#kubectl get svc
#kubectl describe svc mutation-webhook
kubectl describe pod/mutation-webhook-585c789755-qst7j

kubectl logs pod/mutation-webhook-585c789755-qst7j
