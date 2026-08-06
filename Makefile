VERSION ?= 0.4.1
# Base64 Ed25519 public key for self-update verification. Builds without it
# never self-update. The platform publisher (publish_upgrade.php) always
# injects the key from the control plane's config/agent_signing_key.pub.
PUBKEY ?=

LDFLAGS = -X main.version=$(VERSION) -X main.updatePubKeyB64=$(PUBKEY)

.PHONY: build test clean release

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o joinery-agent .

test:
	go test -race ./...

release:
	@chmod +x build_installer.sh
	./build_installer.sh $(VERSION)

clean:
	rm -f joinery-agent joinery-agent-installer.sh
