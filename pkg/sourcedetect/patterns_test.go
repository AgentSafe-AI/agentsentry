package sourcedetect

import "testing"

func TestSignatureForExt(t *testing.T) {
	if got := signatureForExt(".go"); len(got) != 1 || got[0].Language != "go" {
		t.Fatalf("expected go signature, got %#v", got)
	}
	if got := signatureForExt(".tsx"); len(got) != 1 || got[0].Language != "typescript" {
		t.Fatalf("expected typescript signature, got %#v", got)
	}
	if got := signatureForExt(".rb"); len(got) != 0 {
		t.Fatalf("expected no signature, got %#v", got)
	}
}
