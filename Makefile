VERSION ?= dev

.PHONY: build test clean release

build:
	go build -ldflags "-X main.version=$(VERSION)" -o joinery-agent .

test:
	go test -race ./...

release:
	@chmod +x build_installer.sh
	./build_installer.sh $(VERSION)

clean:
	rm -f joinery-agent joinery-agent-installer.sh
