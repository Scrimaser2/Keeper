.PHONY: build macos clean test race fuzz bench

GO ?= go
FUZZTIME ?= 30s

build: macos

macos:
	sh scripts/build-macos-app.sh

clean:
	rm -rf dist

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

fuzz:
	$(GO) test ./internal/vault -run '^$$' -fuzz '^FuzzLegacyVaultDecoder$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/vault -run '^$$' -fuzz '^FuzzStreamIndexParser$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/vault -run '^$$' -fuzz '^FuzzStreamV3CommitParser$$' -fuzztime=$(FUZZTIME)
	$(GO) test ./internal/vault -run '^$$' -fuzz '^FuzzDecryptedStreamManifest$$' -fuzztime=$(FUZZTIME)

bench:
	$(GO) test ./internal/vault -run '^$$' -bench '^BenchmarkStreamReadSampledHeap$$' -benchmem -benchtime=1x
