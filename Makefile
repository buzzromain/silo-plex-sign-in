VERSION ?= 0.1.0
BINARY := plugin
LDFLAGS := -s -w -buildid=
GOFLAGS_BUILD := -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

.PHONY: build build-arm64 release check-version test vet vuln clean

build: check-version
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS_BUILD) -o dist/$(BINARY)-linux-amd64 .

build-arm64: check-version
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS_BUILD) -o dist/$(BINARY)-linux-arm64 .

# release rebuilds both binaries from a clean tree and writes checksums.txt in the Silo catalog format.
release: check-version
	@test -z "$$(git status --porcelain)" || { echo "refusing to release from a dirty tree"; exit 1; }
	rm -f dist/$(BINARY)-linux-amd64 dist/$(BINARY)-linux-arm64 dist/checksums.txt
	$(MAKE) build build-arm64
	cd dist && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 > checksums.txt

# check-version fails when provider.Version, manifest.json and README disagree.
check-version:
	@grep -q 'Version = "$(VERSION)"' provider/provider.go || { echo "provider.Version != $(VERSION)"; exit 1; }
	@grep -q '"version": "$(VERSION)"' manifest.json || { echo "manifest.json != $(VERSION)"; exit 1; }
	@grep -Fq 'Current plugin version: `$(VERSION)`.' README.md || { echo "README.md != $(VERSION)"; exit 1; }

test:
	go test -count=1 -race ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

clean:
	rm -f dist/$(BINARY)-linux-amd64 dist/$(BINARY)-linux-arm64 dist/checksums.txt
