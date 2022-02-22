NAME        := srl/bgp-acl
LAST_COMMIT := $(shell sh -c "git log -1 --pretty=%h")
TODAY       := $(shell sh -c "date +%Y%m%d_%H%M")
TAG         := ${TODAY}.${LAST_COMMIT}
IMG         := ${NAME}:${TAG}
LATEST      := ${NAME}:latest
# HTTP_PROXY  := "http://proxy.lbs.alcatel-lucent.com:8000"

ifndef SR_LINUX_RELEASE
override SR_LINUX_RELEASE="latest"
endif

.PHONY: build build-combined do-build

build: BASEIMG="ghcr.io/nokia/srlinux"
build: do-build

do-build:
	sudo docker build --build-arg SRL_BGL_ACL_RELEASE=${TAG} \
	 --build-arg http_proxy=${HTTP_PROXY} --build-arg https_proxy=${HTTP_PROXY} \
	 --build-arg SR_LINUX_RELEASE="${SR_LINUX_RELEASE}" \
	 --build-arg SR_BASEIMG="${BASEIMG}" -f Dockerfile -t ${IMG} .
	sudo docker tag ${IMG} ${LATEST}

build-combined: BASEIMG="srl/auto-config"
build-combined: do-build

CREATE_CONTAINER := $(shell docker create ${LATEST})
SET_CONTAINER_ID = $(eval CONTAINER_ID=$(CREATE_CONTAINER))
rpm: pipenv
	mkdir -p rpmbuild
	$(SET_CONTAINER_ID)
	docker cp --follow-link ${CONTAINER_ID}:/opt/demo-agents/ rpmbuild/
	docker rm ${CONTAINER_ID}
	find rpmbuild/ -type l -delete # Purge (broken) symlinks
	find rpmbuild/ -name test* | xargs rm -rf # Remove test code
	find rpmbuild/ -name *.so | xargs strip # Strip binaries
	docker run --rm -v ${PWD}:/tmp -w /tmp goreleaser/nfpm package \
    --config /tmp/fpmConfig.yml \
    --target /tmp \
    --packager rpm
	# rm -rf rpmbuild

pipenv:
	sudo docker build --build-arg SRL_BGL_ACL_RELEASE=${TAG} \
	                  --build-arg http_proxy=${HTTP_PROXY} \
										--build-arg https_proxy=${HTTP_PROXY} \
	                  --build-arg SR_LINUX_RELEASE="${SR_LINUX_RELEASE}" \
	                  -f ./Dockerfile.pipenv -t ${IMG} .
	sudo docker tag ${IMG} ${LATEST}
