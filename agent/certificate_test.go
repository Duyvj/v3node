package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowedCertificatePathRejectsTraversalAndFilesOutsideRoots(t *testing.T) {
	root := t.TempDir()
	oldRoots := certificateRoots
	certificateRoots = []string{root}
	defer func() { certificateRoots = oldRoots }()

	valid := filepath.Join(root, "node.crt")
	if err := os.WriteFile(valid, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantResolved, err := filepath.EvalSymlinks(valid)
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := allowedCertificatePath(valid); err != nil || resolved != wantResolved {
		t.Fatalf("valid certificate path rejected: resolved=%q err=%v", resolved, err)
	}

	outside := filepath.Join(t.TempDir(), "secret.pem")
	if err := os.WriteFile(outside, []byte("private material"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := allowedCertificatePath(outside); err == nil {
		t.Fatal("certificate reader accepted a file outside the allowlisted roots")
	}
	if _, err := allowedCertificatePath(filepath.Join(root, "node.key")); err == nil {
		t.Fatal("certificate reader accepted a private-key extension")
	}
}

func TestAllowedCertificatePathBoundsFileSize(t *testing.T) {
	root := t.TempDir()
	oldRoots := certificateRoots
	certificateRoots = []string{root}
	defer func() { certificateRoots = oldRoots }()

	empty := filepath.Join(root, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := allowedCertificatePath(empty); err == nil {
		t.Fatal("certificate reader accepted an empty file")
	}
}
