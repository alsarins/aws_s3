BINARY=s3proxy

# Платформа по умолчанию (текущая)
GOOS=$(shell go env GOOS)
GOARCH=$(shell go env GOARCH)

# Целевая платформа (Linux)
TARGET_GOOS=linux
TARGET_GOARCH=amd64

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
	sudo cp ./bin/$(BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY)

.PHONY: clean
clean:
	rm -rf ./bin
