package xwing

import (
	"bytes"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The shared vector file (specs/post_quantum_sealing.md R9): the draft's X-Wing
// known answers and the v2 seals includes/SealedBox.php made.
type xwingVectors struct {
	Draft string `json:"draft"`
	XWing []struct {
		Seed, PK, ESeed, CT, SS string
	} `json:"xwing"`
	Seal []struct {
		Scope        string `json:"scope"`
		SeedHex      string `json:"seed_hex"`
		PublicB64    string `json:"public_b64"`
		ESeedHex     string `json:"eseed_hex"`
		IVHex        string `json:"iv_hex"`
		PlaintextHex string `json:"plaintext_hex"`
		SealedB64    string `json:"sealed_b64"`
	} `json:"seal"`
}

func loadXWingVectors(t *testing.T) xwingVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/xwing_vector.json")
	if err != nil {
		t.Fatalf("vector file: %v", err)
	}
	var v xwingVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vector file: %v", err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixedMLKEM is the ML-KEM half with the vector's randomness (eseed[0:32]).
func fixedMLKEM(m []byte) MLKEMEncapsulate {
	return func(ek *mlkem.EncapsulationKey768) ([]byte, []byte, error) {
		return mlkemtest.Encapsulate768(ek, m)
	}
}

func TestXWingVectors(t *testing.T) {
	v := loadXWingVectors(t)
	if len(v.XWing) == 0 || len(v.Seal) == 0 {
		t.Fatal("the vector file holds no vectors")
	}
	for i, x := range v.XWing {
		seed, eseed := unhex(t, x.Seed), unhex(t, x.ESeed)
		pk, err := PublicKey(seed)
		if err != nil || hex.EncodeToString(pk) != x.PK {
			t.Fatalf("vector %d: public key from the seed differs (%v)", i+1, err)
		}
		ss, ct, err := EncapsulateWith(pk, eseed[32:], fixedMLKEM(eseed[:32]))
		if err != nil || hex.EncodeToString(ct) != x.CT || hex.EncodeToString(ss) != x.SS {
			t.Fatalf("vector %d: encapsulation differs (%v)", i+1, err)
		}
		got, err := Decapsulate(seed, unhex(t, x.CT))
		if err != nil || hex.EncodeToString(got) != x.SS {
			t.Fatalf("vector %d: decapsulation differs (%v)", i+1, err)
		}
	}
	for _, s := range v.Seal {
		seed, eseed := unhex(t, s.SeedHex), unhex(t, s.ESeedHex)
		pk, _ := base64.StdEncoding.DecodeString(s.PublicB64)
		sealed, err := SealWith(unhex(t, s.PlaintextHex), pk, s.Scope, eseed[32:], unhex(t, s.IVHex), fixedMLKEM(eseed[:32]))
		if err != nil || base64.StdEncoding.EncodeToString(sealed) != s.SealedB64 {
			t.Fatalf("seal %q: not byte for byte what SealedBox made (%v)", s.Scope, err)
		}
		pt, err := Open(sealed, seed, s.Scope)
		if err != nil || !bytes.Equal(pt, unhex(t, s.PlaintextHex)) {
			t.Fatalf("seal %q: does not open (%v)", s.Scope, err)
		}
		other := "dek"
		if s.Scope == "dek" {
			other = "joinery-restore-approval:"
		}
		if _, err := Open(sealed, seed, other); err == nil {
			t.Fatalf("seal %q opened under scope %q", s.Scope, other)
		}
	}
}

func TestSealV2RoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	pk, err := PublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal([]byte("hello"), pk, ScopeDEK)
	if err != nil || len(sealed) != Overhead+5 {
		t.Fatalf("seal: %v len %d", err, len(sealed))
	}
	pt, err := Open(sealed, seed, ScopeDEK)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("open: %v", err)
	}
	if _, err := Open(sealed, bytes.Repeat([]byte{8}, 32), ScopeDEK); err == nil {
		t.Fatal("another seed opened it")
	}
}
