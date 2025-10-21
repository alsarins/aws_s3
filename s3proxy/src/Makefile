BINARY=s3proxy

export GO111MODULE=on
export GO_VERSION=1.23
export CGO_ENABLED=0

GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)

TARGET_GOOS=linux
TARGET_GOARCH=amd64

lint: go-lint

go-lint:
	golangci-lint run -v

.PHONY: all
all: build

build:
	mkdir -p ./bin
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o ./bin/$(BINARY)

build-linux:
	mkdir -p ./bin
	GOOS=$(TARGET_GOOS) GOARCH=$(TARGET_GOARCH) go build -o ./bin/$(BINARY)-linux

.PHONY: install
install: build
	sudo mkdir -p $(DESTDIR)/usr/local/bin/
	sudo install -c -m 755 ./bin/$(BINARY) $(DESTDIR)/usr/local/bin/

.PHONY: clean
clean:
	rm -rf ./bin
