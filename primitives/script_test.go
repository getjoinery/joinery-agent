package primitives

import (
	"strings"
	"testing"
)

// The output cap is the last thing between a root process's transcript and the
// plane that has to read it, and which END it keeps decides whether a result is
// diagnostic or decorative.

func TestShortOutputIsUntouched(t *testing.T) {
	text, dropped := capOutput([]byte("all done\n"), 64)
	if dropped {
		t.Error("nothing should be dropped from output that fits")
	}
	if text != "all done\n" {
		t.Errorf("output that fits should come back verbatim, got %q", text)
	}
}

func TestTheVERDICTAtTheEndSurvivesTruncation(t *testing.T) {
	// The case that made this worth fixing. upgrade.php prints a long transcript
	// and then says how it went; a head-only cap returned the transcript and
	// dropped the verdict, so process_apply_update could not tell an upgrade
	// that halted to refresh its own tooling from one that simply failed.
	const verdict = "PLEASE RE-RUN THE UPGRADE"
	body := strings.Repeat("deploying a file\n", 20000) + verdict + "\n"

	text, dropped := capOutput([]byte(body), MaxScriptOutputBytes)
	if !dropped {
		t.Fatal("this output is well over the cap and should report as dropped")
	}
	if !strings.Contains(text, verdict) {
		t.Error("the verdict at the end of the transcript was dropped — the cap must keep the tail")
	}
}

func TestTheStartOfTheTranscriptSurvivesToo(t *testing.T) {
	// A tail alone can be a page of output with nothing saying what produced it.
	body := "UPGRADE STARTING for release 0.8.352\n" +
		strings.Repeat("deploying a file\n", 20000) + "done\n"

	text, _ := capOutput([]byte(body), MaxScriptOutputBytes)
	if !strings.Contains(text, "UPGRADE STARTING for release 0.8.352") {
		t.Error("the opening lines were dropped; they say what the run was")
	}
	if !strings.Contains(text, "done") {
		t.Error("the closing lines were dropped")
	}
}

func TestTruncationNeverExceedsTheCap(t *testing.T) {
	// The result has to fit inside a body that also carries a log and an
	// envelope. A cap that reports itself but does not hold is worse than none.
	for _, max := range []int{16, 64, 512, 4096, MaxScriptOutputBytes} {
		body := []byte(strings.Repeat("x", max*3+7))
		text, dropped := capOutput(body, max)
		if !dropped {
			t.Errorf("max=%d: oversized output should report as dropped", max)
		}
		if len(text) > max {
			t.Errorf("max=%d: capped output is %d bytes, over the cap", max, len(text))
		}
	}
}

func TestTruncationSaysHowMuchItDropped(t *testing.T) {
	body := []byte(strings.Repeat("x", 5000))
	text, _ := capOutput(body, 1000)
	if !strings.Contains(text, "bytes dropped") {
		t.Errorf("a truncated transcript must say so in the transcript itself, got %q", text)
	}
}

func TestATinyCapKeepsTheEnd(t *testing.T) {
	// Too small to hold the notice. What is kept is the outcome, not the
	// preamble — the same priority as the ordinary path.
	text, dropped := capOutput([]byte("startingXXXXXXXXXXXXXXXXfinished"), 8)
	if !dropped {
		t.Fatal("should report as dropped")
	}
	if len(text) > 8 {
		t.Fatalf("kept %d bytes for a cap of 8", len(text))
	}
	if !strings.Contains(text, "finished") {
		t.Errorf("a cap with no room for a notice should still keep the end, got %q", text)
	}
}

func TestSeamsDoNotProduceHalfCharacters(t *testing.T) {
	// Two seams now instead of one, and both can land inside a multi-byte
	// character. A mangled rune in a transcript reads as corruption on the node
	// rather than as an artefact of the cap.
	body := []byte(strings.Repeat("héllo wörld ", 500))
	text, _ := capOutput(body, 200)

	head, tail, found := strings.Cut(text, "bytes dropped")
	if !found {
		t.Fatal("expected the truncation notice")
	}
	for name, part := range map[string]string{"head": head, "tail": tail} {
		if strings.ContainsRune(part, '�') {
			t.Errorf("the %s seam left a half-written character: %q", name, part)
		}
	}
}

func TestBinaryOutputIsNotEatenByTheSeamTrim(t *testing.T) {
	// Undecodable bytes are not always a seam artefact. A script that printed
	// binary should come back as binary, minus at most a partial character at
	// each cut.
	body := make([]byte, 3000)
	for i := range body {
		body[i] = 0xFF
	}
	text, _ := capOutput(body, 500)
	if len(text) < 400 {
		t.Errorf("binary output was trimmed away to %d bytes; the seam trim should give up quickly", len(text))
	}
}
