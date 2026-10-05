BIN := bin/sbmgr

.PHONY: build test vet check build-all clean

build: ; go build -o $(BIN) ./cmd/sbmgr
test: ; go test ./...
vet: ; go vet ./...
check: ; @test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
build-all:
	@for t in linux/amd64 linux/arm64 windows/amd64 darwin/arm64 darwin/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=""; [ $$os = windows ] && ext=".exe"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="-s -w" -o bin/sbmgr-$$os-$$arch$$ext ./cmd/sbmgr || exit 1; \
		echo "built bin/sbmgr-$$os-$$arch$$ext"; \
	done
clean: ; rm -rf bin
