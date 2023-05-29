DOCKER_REPO=wyx20000905/mutationwebhook

.PHONY: all
all: docker-build docker-push

.PHONY: docker-build
docker-build:
	docker build -t mutationwebhook:cobra .

.PHONY: docker-push
docker-push:
	docker tag mutationwebhook:cobra $(DOCKER_REPO):cobra
	docker push $(DOCKER_REPO):cobra