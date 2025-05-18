# Makefile for airsend

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTIDY=$(GOCMD) mod tidy
GORUN=$(GOCMD) run
BINARY_NAME=airsend
MAIN_FILES=main.go chat-window.go

all: build

build-all:
	$(MAKE) build-linux
	$(MAKE) build-windows
	$(MAKE) build-macos
build-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-linux-amd64 $(MAIN_FILES)

build-windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-windows-amd64.exe $(MAIN_FILES)

build-macos:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINARY_NAME)-macos-arm $(MAIN_FILES)
build:
	$(GOBUILD) -o $(BINARY_NAME) $(MAIN_FILES)

run:
	$(GOTIDY)
	$(GORUN) $(MAIN_FILES) $(ARGS)

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

tidy:
	$(GOTIDY)

.PHONY: all build run clean tidy 