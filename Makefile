GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: authservice installer docker all test clean

authservice:
	env GOOS=linux go build -ldflags "-X intel/isecl/authservice/version.BuildDate=$(BUILDDATE) -X intel/isecl/authservice/version.Version=$(VERSION) -X intel/isecl/authservice/version.GitHash=$(GITCOMMIT)" -o out/authservice

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html


installer: authservice
	mkdir -p out/installer
	cp dist/linux/authservice.service out/installer/authservice.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/db_rotation.sql out/installer/db_rotation.sql
	cp out/authservice out/installer/authservice
	makeself out/installer out/authservice-$(VERSION).bin "Auth Service $(VERSION)" ./install.sh
	cp dist/linux/install_pgdb.sh out/install_pgdb.sh && chmod +x out/install_pgdb.sh

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/authservice:latest --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy} -f ./dist/docker/Dockerfile ./out
	docker save isecl/authservice:latest > ./out/docker-authservice-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-authservice
	cp dist/docker/docker-compose.yml out/docker-authservice/docker-compose
	cp dist/docker/entrypoint.sh out/docker-authservice/entrypoint.sh && chmod +x out/docker-authservice/entrypoint.sh
	cp dist/docker/README.md out/docker-authservice/README.md
	cp out/authservice-$(VERSION).bin out/docker-authservice/authservice-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-authservice/Dockerfile
	zip -r out/docker-authservice.zip out/docker-authservice	

all: test docker

clean:
	rm -f cover.*
	rm -f authservice
	rm -rf out/
