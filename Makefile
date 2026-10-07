VERSION ?= 0.4.1
# Base64 Ed25519 public key for self-update verification. Builds without it
# never self-update. The platform publisher (publish_upgrade.php) always
# injects the key from the control plane's config/agent_signing_key.pub.
PUBKEY ?=
# Release-log keys (releaselog.go), comma-separated: base64 P-256 statement
# keys, and <origin>:<base64 key> checkpoint keys. A build with both holds its
# self-updates to Sigstore's public log; the publisher injects them from
# release_keys/.
STATEMENT_KEYS ?=
LOG_KEYS ?=

LDFLAGS = -X main.version=$(VERSION) -X main.updatePubKeyB64=$(PUBKEY) -X main.releaseStatementKeysB64=$(STATEMENT_KEYS) -X main.releaseLogKeysB64=$(LOG_KEYS)

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
