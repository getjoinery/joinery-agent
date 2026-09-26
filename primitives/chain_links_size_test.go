package primitives

import (
	"fmt"
	"strings"
	"testing"
)

// A chain job carries a signed link for every object in the chain, so it grows
// with runs × artifacts per run. These pin that the longest chain the backup
// engine can write reaches stage_chain and verify_backup, that one link past
// the bound does not, and that no other word gained their larger ceiling.

// realisticLink is a presigned GET the length S3Signer::presign_get produces
// for a long fleet prefix (445 bytes measured 2026-09-26), with the ampersands
// Go's encoder expands, so the byte test is not flattered by short fixtures.
func realisticLink(name string) string {
	base := "https://s3.us-west-004.backblazeb2.com/joinery-fleet-backups/joinery-backups/" +
		"jeremytunnell-site-backups/jeremytunnell/manager/chain-20260924_040025/" + name +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=0000000000000000000000000%2F20260926%2F" +
		"us-west-004%2Fs3%2Faws4_request&X-Amz-Date=20260926T120000Z&X-Amz-Expires=604800" +
		"&X-Amz-SignedHeaders=host&X-Amz-Signature="
	return base + strings.Repeat("a", 64)
}

// longestChainLinks is every object of a 181-run chain of five artifacts each.
func longestChainLinks(runs int) map[string]interface{} {
	links := map[string]interface{}{}
	kinds := []string{"code-%04d.tar.gz.enc", "data-%04d.tar.gz.enc", "pgdata-%04d.tar.gz.enc",
		"meta-%04d.tar.gz.enc", "objects-%04d.json.gz"}
	for seq := 0; seq < runs; seq++ {
		for _, k := range kinds {
			name := fmt.Sprintf(k, seq)
			links[name] = realisticLink(name)
		}
	}
	return links
}

func chainParams(p Primitive, links map[string]interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"chain_id":      "chain-20260924_040025",
		"profile":       "manager",
		"manifest_url":  realisticLink("manifest.json"),
		"artifact_urls": links,
	}
	if strings.HasPrefix(p.Name, "verify_backup") {
		params["level"] = float64(2)
	}
	return params
}

var chainWords = []string{"stage_chain", "verify_backup"}

func TestTheLongestChainFitsTheChainWords(t *testing.T) {
	links := longestChainLinks(181)
	if len(links) != 905 {
		t.Fatalf("fixture built %d links, want 905", len(links))
	}
	for _, name := range chainWords {
		p, ok := Lookup(name)
		if !ok {
			t.Fatalf("%s should be registered", name)
		}
		if p.paramsLimit() != ChainParamsBytes {
			t.Errorf("%s validates under %d bytes, want ChainParamsBytes (%d)", name, p.paramsLimit(), ChainParamsBytes)
		}
		if _, err := ValidateUpTo(p.Params, chainParams(p, links), p.paramsLimit()); err != nil {
			t.Errorf("%s refused the longest chain the engine writes: %v", name, err)
		}
		// The same job under the ordinary ceiling is refused — so the fixture
		// really is past what an ordinary word takes, and proves the ceiling.
		if _, err := Validate(p.Params, chainParams(p, links)); err == nil {
			t.Errorf("%s: the longest chain should not fit the ordinary %d-byte ceiling — the fixture is too small to prove anything",
				name, MaxParamsBytes)
		}
	}
}

func TestOneLinkPastTheBoundIsRefused(t *testing.T) {
	links := map[string]interface{}{}
	for i := 0; i <= chainLinksMax; i++ {
		name := fmt.Sprintf("data-%04d.tar.gz.enc", i)
		links[name] = "https://x.invalid/o?X-Amz-Signature=b"
	}
	for _, name := range chainWords {
		p, _ := Lookup(name)
		if _, err := ValidateUpTo(p.Params, chainParams(p, links), p.paramsLimit()); err == nil {
			t.Errorf("%s accepted %d links, over chainLinksMax (%d)", name, len(links), chainLinksMax)
		}
	}
}

func TestOnlyTheChainWordsCarryTheLargerCeiling(t *testing.T) {
	for _, p := range registry {
		switch p.Name {
		case "stage_chain", "verify_backup":
			continue
		}
		if p.paramsLimit() != MaxParamsBytes {
			t.Errorf("%s validates under %d bytes; only the chain words may exceed MaxParamsBytes (%d)",
				p.Name, p.paramsLimit(), MaxParamsBytes)
		}
	}
}
