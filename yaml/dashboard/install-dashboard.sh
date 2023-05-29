#!/usr/bin/env bash

kubectl apply -f dashboard-install.yaml
kubectl apply -f dash-admin-user.yaml
kubectl -n kubernetes-dashboard describe secret $(kubectl -n kubernetes-dashboard get secret | grep admin-user | awk '{print $1}')
kubectl proxy
