# Heavily inspired by Lighthouse: https://github.com/sigp/lighthouse/blob/stable/Makefile
# and Reth: https://github.com/paradigmxyz/reth/blob/main/Makefile
.DEFAULT_GOAL := help

VERSION := $(shell git describe --tags --always --dirty="-dev")

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: v
v: ## Show the version
	@echo "Version: ${VERSION}"

##@ Build

.PHONY: clean
clean: ## Clean the build directory
	rm -rf build/

.PHONY: build-cli
build-cli: ## Build the CLI
	@mkdir -p ./build
	go build -trimpath -ldflags "-X github.com/ruteri/poc-tee-registry/common.Version=${VERSION}" -v -o ./build/cli cmd/cli/main.go

.PHONY: build-httpserver
build-httpserver: ## Build the HTTP server
	@mkdir -p ./build
	go build -trimpath -ldflags "-X github.com/ruteri/poc-tee-registry/common.Version=${VERSION}" -v -o ./build/httpserver cmd/httpserver/main.go

##@ Test & Development

.PHONY: test
test: ## Run tests
	go test ./...

.PHONY: test-race
test-race: ## Run tests with race detector
	go test -race ./...

.PHONY: lint
lint: ## Run linters
	gofmt -d -s .
	gofumpt -d -extra .
	go vet ./...
	staticcheck ./...
	golangci-lint run
	# nilaway ./...

.PHONY: fmt
fmt: ## Format the code
	gofmt -s -w .
	gci write .
	gofumpt -w -extra .
	go mod tidy

.PHONY: gofumpt
gofumpt: ## Run gofumpt
	gofumpt -l -w -extra .

.PHONY: lt
lt: lint test ## Run linters and tests

.PHONY: cover
cover: ## Run tests with coverage
	go test -coverprofile=/tmp/go-sim-lb.cover.tmp ./...
	go tool cover -func /tmp/go-sim-lb.cover.tmp
	unlink /tmp/go-sim-lb.cover.tmp

.PHONY: cover-html
cover-html: ## Run tests with coverage and open the HTML report
	go test -coverprofile=/tmp/go-sim-lb.cover.tmp ./...
	go tool cover -html=/tmp/go-sim-lb.cover.tmp
	unlink /tmp/go-sim-lb.cover.tmp

.PHONY: docker-cli
docker-cli: ## Build the CLI Docker image
	DOCKER_BUILDKIT=1 docker build \
		--platform linux/amd64 \
		--build-arg VERSION=${VERSION} \
		--file cli.dockerfile \
		--tag your-project \
	.

.PHONY: docker-httpserver
docker-httpserver: ## Build the HTTP server Docker image
	DOCKER_BUILDKIT=1 docker build \
		--platform linux/amd64 \
		--build-arg VERSION=${VERSION} \
		--file httpserver.dockerfile \
		--tag your-project \
	.

.PHONY: bindings
bindings: ## Generate golang bindings for the contract
	forge build ./src/OnchainRegistry.sol
	forge build ./src/KMS.sol
	jq '.abi' out/OnchainRegistry.sol/Registry.json > Registry.abi
	jq '.abi' out/KMS.sol/KMS.json > KMS.abi
	jq -r '.bytecode.object' out/OnchainRegistry.sol/Registry.json > Registry.bin
	jq -r '.bytecode.object' out/KMS.sol/KMS.json > KMS.bin
	abigen --abi=Registry.abi --bin=Registry.bin --pkg=registry --out=bindings/registry/registry.go
	abigen --abi=KMS.abi --bin=KMS.bin --pkg=kms --out=bindings/kms/kms.go

.PHONY: deploy-registry
deploy-registry: ## Deploy and verify registry on Sepolia. Requires etherscan API key. Asks for private key.
	forge c --verify --rpc-url https://1rpc.io/sepolia --verifier etherscan -i -C contracts src/OnchainRegistry.sol:Registry --broadcast

.PHONY: deploy-kms
deploy-kms: ## Deploy and verify on Sepolia. Requires etherscan API key. Asks for private key.
	forge c --verify --rpc-url https://1rpc.io/sepolia --verifier etherscan -i -C contracts src/KMS.sol:KMS --broadcast

.PHONY: context
context: ## Generate godoc for all files
	# Needs `go install github.com/ruteri/gocontext@latest`
	gocontext -verbose -exclude bindings/registry,lib,metrics -include interfaces -clean
