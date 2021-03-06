GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: authservice aas-manager installer docker all test clean

authservice:
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X intel/isecl/authservice/v3/version.BuildDate=$(BUILDDATE) -X intel/isecl/authservice/v3/version.Version=$(VERSION) -X intel/isecl/authservice/v3/version.GitHash=$(GITCOMMIT)" -o out/authservice

aas-manager:
	cd dist/linux/aas-manager/ && make

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

swagger-get:
	wget https://github.com/go-swagger/go-swagger/releases/download/v0.21.0/swagger_linux_amd64 -O /usr/local/bin/swagger
	chmod +x /usr/local/bin/swagger
	wget https://repo1.maven.org/maven2/io/swagger/codegen/v3/swagger-codegen-cli/3.0.16/swagger-codegen-cli-3.0.16.jar -O /usr/local/bin/swagger-codegen-cli.jar

swagger-doc:
	mkdir -p out/swagger
	/usr/local/bin/swagger generate spec -o ./out/swagger/openapi.yml --scan-models
	java -jar /usr/local/bin/swagger-codegen-cli.jar generate -i ./out/swagger/openapi.yml -o ./out/swagger/ -l html2 -t ./swagger/templates/

swagger: swagger-get swagger-doc

installer: authservice aas-manager
	mkdir -p out/installer
	cp dist/linux/authservice.service out/installer/authservice.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/db_rotation.sql out/installer/db_rotation.sql
	cp out/authservice out/installer/authservice
	makeself out/installer out/authservice-$(VERSION).bin "Auth Service $(VERSION)" ./install.sh
	cp dist/linux/install_pgdb.sh out/install_pgdb.sh && chmod +x out/install_pgdb.sh
	cp dist/linux/create_db.sh out/create_db.sh && chmod +x out/create_db.sh
	mv dist/linux/aas-manager/populate-users out/populate-users.sh && chmod +x out/populate-users.sh

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/authservice:$(VERSION) --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy} -f ./dist/docker/Dockerfile ./out
	docker save isecl/authservice:$(VERSION) > ./out/docker-authservice-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-authservice
	cp dist/docker/docker-compose.yml out/docker-authservice/docker-compose
	cp dist/docker/entrypoint.sh out/docker-authservice/entrypoint.sh && chmod +x out/docker-authservice/entrypoint.sh
	cp dist/docker/README.md out/docker-authservice/README.md
	cp out/authservice-$(VERSION).bin out/docker-authservice/authservice-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-authservice/Dockerfile
	zip -r out/docker-authservice.zip out/docker-authservice	

all: clean installer test

clean:
	rm -f cover.*
	rm -f authservice
	rm -rf out/
