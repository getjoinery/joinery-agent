package primitives

import (
	"errors"
	"strings"
	"testing"
)

// An agent that cannot verify anything says why: a build with no release key
// names the build, so the plane does not chase a manifest that would change
// nothing. Every reason keeps the phrase the plane classifies on.
func TestUnavailableVerifierNamesItsReason(t *testing.T) {
	for _, reason := range []error{ErrNoReleaseKey, ErrBadReleaseKey, ErrNoSiteTree} {
		err := UnavailableVerifier{Reason: reason}.Verify("public_html/utils/upgrade.php")
		if !errors.Is(err, reason) {
			t.Errorf("refused with %v, want %v", err, reason)
		}
		if !strings.Contains(err.Error(), "can be verified before running as root") {
			t.Errorf("%q lacks the plane's classification phrase", err)
		}
	}
	if !strings.Contains(ErrNoReleaseKey.Error(), "no release key") {
		t.Errorf("the no-key refusal must name the missing key: %q", ErrNoReleaseKey)
	}
	if err := (UnavailableVerifier{}).Verify("x"); !errors.Is(err, ErrNoSiteTree) {
		t.Errorf("the zero value refuses with %v, want ErrNoSiteTree", err)
	}
}
