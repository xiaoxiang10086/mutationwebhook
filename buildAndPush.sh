#!/usr/bin/env bash

docker build -t mutationwebhook:v1.0 .
docker tag mutationwebhook:v1.0 wyx20000905/mutationwebhook:v1.0
docker push wyx20000905/mutationwebhook:v1.0