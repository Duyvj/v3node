package panel

import (
	"strings"
	"testing"
)

func TestMessagePackRejectsMalformedShapes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		data []byte
	}{
		{"not map", []byte{0x90}},
		{"missing users", []byte{0x81, 0xa1, 'x', 0xc0}},
		{"users not array", []byte{0x81, 0xa5, 'u', 's', 'e', 'r', 's', 0x80}},
		{"truncated", []byte{0x81, 0xa5, 'u', 's', 'e', 'r', 's', 0x91}},
		{"trailing", append(messagePackUserEnvelope(), 0xc0)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeUsersMessagePack(test.data, 10); err == nil {
				t.Fatal("decodeUsersMessagePack() unexpectedly succeeded")
			}
		})
	}
}

func TestMessagePackRejectsExcessiveNesting(t *testing.T) {
	t.Parallel()
	data := []byte{0x82, 0xa1, 'x'}
	for range maxMessagePackDepth + 1 {
		data = append(data, 0x91)
	}
	data = append(data, 0xc0)
	data = appendMessagePackString(data, "users")
	data = append(data, 0x90)
	_, err := decodeUsersMessagePack(data, 10)
	if err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("decodeUsersMessagePack() error = %v", err)
	}
}

func FuzzDecodeUsersMessagePack(f *testing.F) {
	f.Add(messagePackUserEnvelope())
	f.Add([]byte{0x81, 0xa5, 'u', 's', 'e', 'r', 's', 0x90})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeUsersMessagePack(data, 16)
	})
}
