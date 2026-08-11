// Package updater downloads a release installer only after verifying the
// checksum published in the same immutable GitHub release.
package updater

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	defaultAPIBase = "https://api.github.com"
	defaultRepo    = "Duyvj/v3node"
	maxAPIBytes    = 1 << 20
	maxAssetBytes  = 2 << 20
)

var releaseTagPattern = regexp.MustCompile(`^v?[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?(?:[+][0-9A-Za-z.-]+)?$`)

type Options struct {
	APIBase           string
	Repository        string
	Version           string
	UserAgent         string
	HTTPClient        *http.Client
	IncludePrerelease bool
	// AllowHTTP exists only for local tests. Production callers leave it false.
	AllowHTTP bool
}

type Result struct {
	Tag  string
	Path string
}

type release struct {
	TagName    string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// DownloadInstaller resolves a release, validates SHA256SUMS, and writes the
// verified installer to a private temporary file. The caller owns the file.
func DownloadInstaller(ctx context.Context, opts Options) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("updater: context is required")
	}
	if opts.APIBase == "" {
		opts.APIBase = defaultAPIBase
	}
	if opts.Repository == "" {
		opts.Repository = defaultRepo
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "v3node-updater"
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if err := validateEndpoint(opts.APIBase, opts.AllowHTTP); err != nil {
		return Result{}, fmt.Errorf("updater API: %w", err)
	}
	parts := strings.Split(opts.Repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Result{}, errors.New("updater: repository must be owner/name")
	}

	rel, err := resolveRelease(ctx, opts, parts[0], parts[1])
	if err != nil {
		return Result{}, err
	}
	installerAsset, checksumAsset, err := requiredAssets(rel)
	if err != nil {
		return Result{}, err
	}
	checksums, err := fetchAsset(ctx, opts, checksumAsset)
	if err != nil {
		return Result{}, fmt.Errorf("download SHA256SUMS: %w", err)
	}
	expected, err := installerChecksum(checksums)
	if err != nil {
		return Result{}, err
	}
	installer, err := fetchAsset(ctx, opts, installerAsset)
	if err != nil {
		return Result{}, fmt.Errorf("download install.sh: %w", err)
	}
	actual := sha256.Sum256(installer)
	if !bytes.Equal(actual[:], expected) {
		return Result{}, errors.New("updater: install.sh SHA256 does not match SHA256SUMS")
	}

	file, err := os.CreateTemp("", "v3node-install-*.sh")
	if err != nil {
		return Result{}, fmt.Errorf("create installer temporary file: %w", err)
	}
	name := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(0o700); err != nil {
		return Result{}, fmt.Errorf("secure installer permissions: %w", err)
	}
	if _, err := file.Write(installer); err != nil {
		return Result{}, fmt.Errorf("write installer: %w", err)
	}
	if err := file.Sync(); err != nil {
		return Result{}, fmt.Errorf("sync installer: %w", err)
	}
	if err := file.Close(); err != nil {
		return Result{}, fmt.Errorf("close installer: %w", err)
	}
	remove = false
	return Result{Tag: rel.TagName, Path: name}, nil
}

func resolveRelease(ctx context.Context, opts Options, owner, repository string) (release, error) {
	base := strings.TrimRight(opts.APIBase, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repository) + "/releases"
	if opts.Version != "" {
		if !releaseTagPattern.MatchString(opts.Version) {
			return release{}, fmt.Errorf("updater: invalid release version %q", opts.Version)
		}
		tag := opts.Version
		if !strings.HasPrefix(tag, "v") {
			tag = "v" + tag
		}
		var result release
		if err := fetchJSON(ctx, opts, base+"/tags/"+url.PathEscape(tag), &result); err != nil {
			return release{}, fmt.Errorf("resolve release %s: %w", tag, err)
		}
		if result.Draft {
			return release{}, fmt.Errorf("updater: release %s is still a draft", tag)
		}
		return result, nil
	}

	var candidates []release
	if err := fetchJSON(ctx, opts, base+"?per_page=20", &candidates); err != nil {
		return release{}, fmt.Errorf("resolve latest release: %w", err)
	}
	for _, candidate := range candidates {
		if !candidate.Draft && (opts.IncludePrerelease || !candidate.Prerelease) && releaseTagPattern.MatchString(candidate.TagName) {
			return candidate, nil
		}
	}
	return release{}, errors.New("updater: repository has no published release")
}

func fetchJSON(ctx context.Context, opts Options, endpoint string, destination any) error {
	body, err := fetch(ctx, opts, endpoint, maxAPIBytes, 0)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode GitHub response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode GitHub response: trailing data")
		}
		return fmt.Errorf("decode trailing GitHub response: %w", err)
	}
	return nil
}

func fetchAsset(ctx context.Context, opts Options, item asset) ([]byte, error) {
	if item.Size < 0 || item.Size > maxAssetBytes {
		return nil, fmt.Errorf("asset %s has invalid size %d", item.Name, item.Size)
	}
	return fetch(ctx, opts, item.URL, maxAssetBytes, item.Size)
}

func fetch(ctx context.Context, opts Options, endpoint string, limit, expectedSize int64) ([]byte, error) {
	if err := validateEndpoint(endpoint, opts.AllowHTTP); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", opts.UserAgent)
	response, err := opts.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if err := validateEndpoint(response.Request.URL.String(), opts.AllowHTTP); err != nil {
		return nil, fmt.Errorf("unsafe redirect: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, errors.New("response exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("response exceeds size limit")
	}
	if expectedSize > 0 && int64(len(data)) != expectedSize {
		return nil, fmt.Errorf("asset size is %d, expected %d", len(data), expectedSize)
	}
	return data, nil
}

func requiredAssets(rel release) (asset, asset, error) {
	var installer, checksums asset
	for _, item := range rel.Assets {
		switch item.Name {
		case "install.sh":
			installer = item
		case "SHA256SUMS":
			checksums = item
		}
	}
	if rel.TagName == "" || installer.URL == "" || checksums.URL == "" {
		return asset{}, asset{}, errors.New("updater: release is missing install.sh or SHA256SUMS")
	}
	return installer, checksums, nil
}

func installerChecksum(data []byte) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxAssetBytes)
	var result []byte
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != path.Base("install.sh") {
			continue
		}
		if result != nil {
			return nil, errors.New("updater: SHA256SUMS contains duplicate install.sh entries")
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("updater: install.sh checksum is invalid")
		}
		result = decoded
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	if result == nil {
		return nil, errors.New("updater: SHA256SUMS has no install.sh entry")
	}
	return result, nil
}

func validateEndpoint(raw string, allowHTTP bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL must be absolute and contain no credentials or fragment")
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return errors.New("URL must use HTTPS")
	}
	return nil
}
