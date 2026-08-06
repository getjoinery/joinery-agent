package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"golang.org/x/crypto/nacl/secretbox"
)

// Backup-target credentials never travel inside a persisted job command. The
// PHP builder emits a placeholder token and the agent substitutes the real
// credentials in memory immediately before a step runs. The credentials are
// stored SecretBox-encrypted at rest (matching includes/SecretBox.php), so
// resolving a placeholder means: load the target's stored value, unseal it
// with the site's secret_box_key, and splice base64(json(creds)) into the
// command where the token was.
//
// Two tokens name two slots on the target:
//   __SM_CREDS_<id>__       the main credential (bkt_credentials)
//   __SM_NODE_CREDS_<id>__  the node-facing write-only credential
//                           (bkt_node_credentials)
// The PHP builder decides which token a step carries; the agent resolves
// exactly the slot the token names and never falls back to the other — a job
// built against a slot that has since been emptied must fail visibly rather
// than run with a more powerful credential than intended.

var credPlaceholderRe = regexp.MustCompile(`__SM_(NODE_)?CREDS_(\d+)__`)

// decodeSecretBoxKey decodes the standard-base64 secret_box_key into 32 bytes,
// matching SecretBox's own key handling.
func decodeSecretBoxKey(encoded string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("secret_box_key is not valid base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("secret_box_key must decode to 32 bytes, got %d", len(raw))
	}
	var key [32]byte
	copy(key[:], raw)
	return &key, nil
}

// secretBoxDecrypt opens a blob produced by SecretBox::encrypt. The wire format
// is "v1.<algo>.<b64url nonce>.<b64url cipher>"; algo is "sodium"
// (XSalsa20-Poly1305, combined MAC) or "aesgcm" (AES-256-GCM, 16-byte tag
// prepended to the ciphertext).
func secretBoxDecrypt(blob string, key *[32]byte) (string, error) {
	parts := splitN(blob, '.', 4)
	if len(parts) != 4 || parts[0] != "v1" {
		return "", fmt.Errorf("malformed SecretBox blob")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("bad SecretBox nonce encoding: %w", err)
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("bad SecretBox ciphertext encoding: %w", err)
	}

	switch parts[1] {
	case "sodium":
		if len(nonce) != 24 {
			return "", fmt.Errorf("SecretBox sodium nonce must be 24 bytes, got %d", len(nonce))
		}
		var n [24]byte
		copy(n[:], nonce)
		plain, ok := secretbox.Open(nil, ct, &n, key)
		if !ok {
			return "", fmt.Errorf("SecretBox sodium open failed (tampered or wrong key)")
		}
		return string(plain), nil

	case "aesgcm":
		if len(ct) < 16 {
			return "", fmt.Errorf("SecretBox aesgcm ciphertext too short")
		}
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		// PHP prepends the 16-byte tag; Go's GCM wants it appended.
		tag, body := ct[:16], ct[16:]
		reordered := append(append([]byte{}, body...), tag...)
		plain, err := gcm.Open(nil, nonce, reordered, nil)
		if err != nil {
			return "", fmt.Errorf("SecretBox aesgcm open failed (tampered or wrong key)")
		}
		return string(plain), nil

	default:
		return "", fmt.Errorf("unknown SecretBox algorithm %q", parts[1])
	}
}

// splitN splits s on sep into at most n parts (like strings.SplitN but kept
// local to avoid importing strings just for this).
func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// resolveTargetCredsJSON turns a stored bkt_credentials value into plaintext
// credential JSON. The sealed shape is {"enc":"<SecretBox blob>"}; a legacy
// plaintext credential object is returned unchanged.
func resolveTargetCredsJSON(raw string, key *[32]byte) (string, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		// Not an object we recognise — hand it back as-is.
		return raw, nil
	}
	encRaw, ok := obj["enc"]
	if !ok {
		return raw, nil // legacy plaintext credentials
	}
	var enc string
	if err := json.Unmarshal(encRaw, &enc); err != nil {
		return raw, nil
	}
	if !looksSecretBoxEncrypted(enc) {
		return raw, nil
	}
	if key == nil {
		return "", fmt.Errorf("credentials are encrypted but no secret_box_key is configured")
	}
	return secretBoxDecrypt(enc, key)
}

func looksSecretBoxEncrypted(v string) bool {
	return len(v) >= 10 && (v[:10] == "v1.sodium." || v[:10] == "v1.aesgcm.")
}

// substituteCredPlaceholders replaces every credential token in cmd with
// base64(json(creds)) for that target. loadRaw returns a target's raw
// bkt_credentials value; loadNodeRaw its raw bkt_node_credentials value
// (called only for __SM_NODE_CREDS_<id>__ tokens). Any lookup/decrypt failure
// aborts the step so a command never runs with empty or wrong credentials.
func substituteCredPlaceholders(cmd string, key *[32]byte, loadRaw func(int64) (string, error), loadNodeRaw func(int64) (string, error)) (string, error) {
	matches := credPlaceholderRe.FindAllStringSubmatch(cmd, -1)
	if len(matches) == 0 {
		return cmd, nil
	}

	// Resolve each distinct token once.
	resolved := make(map[string]string)
	for _, m := range matches {
		token, isNode, idStr := m[0], m[1] != "", m[2]
		if _, done := resolved[token]; done {
			continue
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return "", fmt.Errorf("bad credential placeholder %q: %w", token, err)
		}
		load := loadRaw
		slot := "credentials"
		if isNode {
			load = loadNodeRaw
			slot = "node credentials"
		}
		raw, err := load(id)
		if err != nil {
			return "", fmt.Errorf("resolving %s placeholder for target #%d: %w", slot, id, err)
		}
		plainJSON, err := resolveTargetCredsJSON(raw, key)
		if err != nil {
			return "", fmt.Errorf("unsealing %s for target #%d: %w", slot, id, err)
		}
		resolved[token] = base64.StdEncoding.EncodeToString([]byte(plainJSON))
	}

	out := credPlaceholderRe.ReplaceAllStringFunc(cmd, func(token string) string {
		return resolved[token]
	})
	return out, nil
}
