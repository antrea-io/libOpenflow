GO                 ?= go

all: test

.PHONY: test
test:
	$(GO) test -v -coverprofile coverage.txt -covermode=atomic -coverpkg=antrea.io/libOpenflow/common/...,antrea.io/libOpenflow/openflow15/...,antrea.io/libOpenflow/protocol/...,antrea.io/libOpenflow/util/...  antrea.io/libOpenflow/...

# code linting
.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ v1.41.1

.PHONY: golangci
golangci: .golangci-bin
	@echo "===> Running golangci <==="
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml

.PHONY: golangci-fix
golangci-fix: .golangci-bin
	@echo "===> Running golangci-fix <==="
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml --fix
