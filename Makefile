NAME := Gocks
GO_BUILD := GO111MODULE=on GONOSUMDB=* CGO_ENABLED=0 go build --ldflags="-s -w" -a
DIRECTORY := ./bin
PLATFORMS := linux_amd64 linux_arm64 windows_amd64

all: $(PLATFORMS)

$(DIRECTORY):
	mkdir -p $(DIRECTORY)

$(PLATFORMS): %: $(DIRECTORY)
	$(eval GOOS := $(word 1,$(subst _, ,$@)))
	$(eval GOARCH := $(word 2,$(subst _, ,$@)))
	$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,))
	rm -f $(DIRECTORY)/$(NAME)_$@$(EXT)
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO_BUILD) -o $(DIRECTORY)/$(NAME)_$@$(EXT) .

.PHONY: all $(PLATFORMS)