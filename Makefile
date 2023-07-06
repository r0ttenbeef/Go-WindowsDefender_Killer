EXECUTABLE=DisableWinDefend
AUTHOR=r0ttenbeef
VERSION=1.0
RELEASE=$(EXECUTABLE)$(VERSION).exe
DEBUG=$(EXECUTABLE)$(VERSION)_debug.exe

define ANNOUNCE_BODY
╦ ╦┬┌┐┌╔╦╗┌─┐┌─┐┌─┐┌┐┌┌┬┐   ╦╔═┬┬  ┬  ┌─┐┬─┐
║║║││││ ║║├┤ ├┤ ├┤ │││ ││───╠╩╗││  │  ├┤ ├┬┘
╚╩╝┴┘└┘═╩╝└─┘└  └─┘┘└┘─┴┘   ╩ ╩┴┴─┘┴─┘└─┘┴└─
Author: $(AUTHOR) -- Version: $(VERSION)
---
endef

export ANNOUNCE_BODY
.PHONY: release debug

release: init build_release
debug: init build_debug

init:
	@echo "$$ANNOUNCE_BODY"
	@echo "[*]Generate Modules"
	@if [ ! -f go.mod ]; then\
	   	go mod init main;\
		go get -v golang.org/x/sys/windows/registry;\
	fi
	@echo "[*]Generate resource file"
	@go generate

build_release:
	@echo "[*]Compiling release build for windows x64 architicture"
	@env GOOS=windows GOARCH=amd64 go build -v -o $(RELEASE) -ldflags="-s -w -X main.Version=$(VERSION)"
	@go clean -cache
	@echo "$(EXECUTABLE) 64bit release version compiled successfully"
		
build_debug:
	@echo "[*]Compiling debug build for windows x64 architicture"
	@env GOOS=windows GOARCH=amd64 go build -v -o $(DEBUG)
	@go clean -cache
	@echo "$(EXECUTABLE) debug version compiled successfully"
