package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectionsSnapshot(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Errorf("Authorization = %q", got)
		}
		if r.Method == http.MethodDelete {
			if r.URL.Path != "/connections/abcd-1234" {
				t.Errorf("DELETE path = %q", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"downloadTotal":7,"ignored":{"nested":[1,2,3]},"connections":[{"id":"abcd-1234","metadata":{"sourceIP":"203.0.113.4","user":"uid-9"},"upload":5,"download":7}]}`)
	}))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()
	client, err := NewConnectionsClient(strings.TrimPrefix(server.URL, "http://"), time.Second, 10, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].User != "uid-9" || got[0].SourceIP.String() != "203.0.113.4" {
		t.Fatalf("unexpected result: %#v", got)
	}
	if err := client.Close(context.Background(), "abcd-1234"); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeConnectionsEnforcesStreamingBounds(t *testing.T) {
	payload := `{"connections":[` +
		`{"id":"first","metadata":{"sourceIP":"192.0.2.1","user":"uid-1"}},` +
		`{"id":"second","metadata":{"sourceIP":"192.0.2.2","user":"uid-2"}}]}`
	if _, err := decodeConnections(strings.NewReader(payload), 1); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("connection count limit error = %v", err)
	}
	if _, err := decodeConnections(strings.NewReader(`{"connections":[]} {}`), 1); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing JSON error = %v", err)
	}
	if _, err := decodeConnections(strings.NewReader(`{"downloadTotal":0}`), 1); err == nil || !strings.Contains(err.Error(), "no connections") {
		t.Fatalf("missing connections error = %v", err)
	}
}
