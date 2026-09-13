BINARY := krakenseye

.PHONY: all build test vet dist-arm64 dist-amd64 dist clean

all: test vet build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/krakenseye

test:
	go test -count=1 ./...

vet:
	go vet ./...

dist-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/$(BINARY)-arm64 ./cmd/krakenseye
	upx -9 dist/$(BINARY)-arm64 || true

dist-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/$(BINARY)-amd64 ./cmd/krakenseye
	upx -9 dist/$(BINARY)-amd64 || true

dist: dist-amd64 dist-arm64
	ls -la dist/

clean:
	rm -rf dist $(BINARY)