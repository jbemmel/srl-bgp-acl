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
