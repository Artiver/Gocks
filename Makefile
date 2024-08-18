NAME := Gocks
GO_BUILD := go build --ldflags="-s -w"
DIRECTORY := bin
PLATFORMS := linux_amd64 linux_arm64 windows_amd64

set_env:
ifeq ($(OS),Windows_NT)
	set GO111MODULE=on && set GONOSUMDB=* && set CGO_ENABLED=0
else
	export GO111MODULE=on GONOSUMDB=* CGO_ENABLED=0
endif

$(PLATFORMS):
	$(eval GOOS := $(word 1,$(subst _, ,$@)))
	$(eval GOARCH := $(word 2,$(subst _, ,$@)))
	$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,))
ifeq ($(OS),Windows_NT)
	set GOOS=$(GOOS) && set GOARCH=$(GOARCH)
else
	export GOOS=$(GOOS) GOARCH=$(GOARCH)
endif
	$(GO_BUILD) -o $(DIRECTORY)/$(NAME)_$@$(EXT) .

all: set_env $(PLATFORMS)

.PHONY: all $(PLATFORMS)
