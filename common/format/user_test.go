package format

import (
	"strings"
	"testing"
)

func TestRedactUserTagDoesNotExposeBearerCredential(t *testing.T) {
	const credential = "01234567-89ab-cdef-0123-456789abcdef"
	redacted := RedactUserTag(UserTag("node", credential))
	if strings.Contains(redacted, credential) || strings.Contains(redacted, "89ab") {
		t.Fatalf("redacted user label exposed credential material: %q", redacted)
	}
	if !strings.HasPrefix(redacted, "node|user-") {
		t.Fatalf("unexpected redacted label: %q", redacted)
	}
	if redacted != RedactUserTag(UserTag("node", credential)) {
		t.Fatal("redaction is not stable")
	}
}

func TestUserTagUsesHashedRuntimeIdentity(t *testing.T) {
	const credential = "01234567-89ab-cdef-0123-456789abcdef"
	tag := UserTag("node", credential)
	if strings.Contains(tag, credential) || !strings.HasPrefix(tag, "node|h:") {
		t.Fatalf("runtime user tag exposed the bearer credential: %q", tag)
	}
	legacyDigest := UserCredentialDigest("node|" + credential)
	hashedDigest := UserCredentialDigest(tag)
	if legacyDigest != hashedDigest {
		t.Fatal("hashed runtime tag changed the rolling-upgrade credential identity")
	}
}
