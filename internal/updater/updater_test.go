package updater

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestDownloadInstallerLatestPrerelease(t *testing.T) {
	installer := []byte("#!/usr/bin/env bash\necho verified\n")
	digest := sha256.Sum256(installer)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/Duyvj/v3node/releases":
			fmt.Fprintf(writer, `[{"tag_name":"v0.2.0-beta.1","draft":false,"assets":[{"name":"install.sh","browser_download_url":%q,"size":%d},{"name":"SHA256SUMS","browser_download_url":%q,"size":%d}]}]`,
				server.URL+"/install.sh", len(installer), server.URL+"/SHA256SUMS", 77)
		case "/install.sh":
			_, _ = writer.Write(installer)
		case "/SHA256SUMS":
			fmt.Fprintf(writer, "%x *install.sh\n", digest)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	result, err := DownloadInstaller(context.Background(), Options{
		APIBase:           server.URL,
		HTTPClient:        server.Client(),
		AllowHTTP:         true,
		IncludePrerelease: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(result.Path)
	if result.Tag != "v0.2.0-beta.1" {
		t.Fatalf("tag = %q", result.Tag)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(installer) {
		t.Fatal("downloaded installer differs")
	}
	info, err := os.Stat(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("temporary installer mode = %o", info.Mode().Perm())
	}
}

func TestResolveLatestSkipsPrereleaseOnStableChannel(t *testing.T) {
	installer := []byte("#!/usr/bin/env bash\n")
	digest := sha256.Sum256(installer)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/Duyvj/v3node/releases":
			fmt.Fprintf(writer, `[{"tag_name":"v2.0.0-beta.1","draft":false,"prerelease":true,"assets":[]},{"tag_name":"v1.9.0","draft":false,"prerelease":false,"assets":[{"name":"install.sh","browser_download_url":%q,"size":%d},{"name":"SHA256SUMS","browser_download_url":%q,"size":%d}]}]`,
				server.URL+"/install.sh", len(installer), server.URL+"/SHA256SUMS", 77)
		case "/install.sh":
			_, _ = writer.Write(installer)
		case "/SHA256SUMS":
			fmt.Fprintf(writer, "%x *install.sh\n", digest)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	result, err := DownloadInstaller(context.Background(), Options{
		APIBase:    server.URL,
		HTTPClient: server.Client(),
		AllowHTTP:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(result.Path)
	if result.Tag != "v1.9.0" {
		t.Fatalf("stable channel selected %q", result.Tag)
	}
}

func TestDownloadInstallerSpecificVersionRejectsChecksumMismatch(t *testing.T) {
	installer := []byte("not the expected installer")
	checksum := strings.Repeat("0", 64) + "  install.sh\n"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/Duyvj/v3node/releases/tags/v1.2.3":
			fmt.Fprintf(writer, `{"tag_name":"v1.2.3","draft":false,"assets":[{"name":"install.sh","browser_download_url":%q,"size":%d},{"name":"SHA256SUMS","browser_download_url":%q,"size":%d}]}`,
				server.URL+"/install.sh", len(installer), server.URL+"/SHA256SUMS", len(checksum))
		case "/install.sh":
			_, _ = writer.Write(installer)
		case "/SHA256SUMS":
			_, _ = writer.Write([]byte(checksum))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	_, err := DownloadInstaller(context.Background(), Options{
		APIBase:    server.URL,
		Version:    "1.2.3",
		HTTPClient: server.Client(),
		AllowHTTP:  true,
	})
	if err == nil || !strings.Contains(err.Error(), "SHA256") {
		t.Fatalf("error = %v", err)
	}
}

func TestDownloadInstallerRejectsInvalidVersionBeforeNetwork(t *testing.T) {
	_, err := DownloadInstaller(context.Background(), Options{APIBase: "https://api.github.com", Version: "../../main"})
	if err == nil || !strings.Contains(err.Error(), "invalid release version") {
		t.Fatalf("error = %v", err)
	}
}

func TestInstallerChecksumRejectsDuplicates(t *testing.T) {
	data := []byte(strings.Repeat("a", 64) + " *install.sh\n" + strings.Repeat("b", 64) + "  install.sh\n")
	if _, err := installerChecksum(data); err == nil {
		t.Fatal("duplicate checksum accepted")
	}
}
