NAME := Gocks
GO_BUILD := go build -trimpath --ldflags="-s -w"
DIRECTORY := bin
PLATFORMS := darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64 windows_arm64

$(PLATFORMS):
	$(eval GOOS := $(word 1,$(subst _, ,$@)))
	$(eval GOARCH := $(word 2,$(subst _, ,$@)))
	$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,))
ifeq ($(OS),Windows_NT)
	set GO111MODULE=on&& set GONOSUMDB=*&& set CGO_ENABLED=0&& set GOOS=$(GOOS)&& set GOARCH=$(GOARCH)&& $(GO_BUILD) -o $(DIRECTORY)/$(NAME)_$@$(EXT) .
else
	export GO111MODULE=on GONOSUMDB=* CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) && $(GO_BUILD) -o $(DIRECTORY)/$(NAME)_$@$(EXT) .
endif

all: $(PLATFORMS)

.PHONY: all $(PLATFORMS)
