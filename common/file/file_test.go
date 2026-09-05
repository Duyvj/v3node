package file

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularFileLimitedRejectsOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "material.pem")
	if err := os.WriteFile(path, []byte("0123456789abcdefg"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRegularFileLimited(path, 16); err == nil {
		t.Fatal("oversized file was read")
	}
	data, err := ReadRegularFileLimited(path, 17)
	if err != nil || string(data) != "0123456789abcdefg" {
		t.Fatalf("bounded regular file was not read: data=%q err=%v", data, err)
	}
}
