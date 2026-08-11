package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const apiSecretFile = "api.secret"

// LoadOrCreateAPISecret returns the persistent bearer secret shared with the
// loopback connections API. The secret is stored outside engine.json so a
// controller restart keeps the same authenticated last-known-good generation.
func LoadOrCreateAPISecret(stateDirectory string) (string, error) {
	if stateDirectory == "" || !filepath.IsAbs(stateDirectory) {
		return "", errors.New("API secret state directory must be absolute")
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create API secret state directory: %w", err)
	}
	path := filepath.Join(stateDirectory, apiSecretFile)
	if secret, err := readAPISecret(path); err == nil {
		return secret, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	random := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", fmt.Errorf("generate connections API secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(random)
	clear(random)

	file, err := os.CreateTemp(stateDirectory, ".api-secret-*")
	if err != nil {
		return "", fmt.Errorf("stage connections API secret: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("protect connections API secret: %w", err)
	}
	if _, err := io.WriteString(file, secret+"\n"); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write connections API secret: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync connections API secret: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close connections API secret: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return "", fmt.Errorf("activate connections API secret: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(stateDirectory)
		if err != nil {
			return "", fmt.Errorf("open API secret state directory: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return "", errors.Join(syncErr, closeErr)
		}
	}
	return secret, nil
}

func readAPISecret(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("connections API secret must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("connections API secret permissions are too broad")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil {
		return "", fmt.Errorf("read connections API secret: %w", err)
	}
	if len(data) > 1024 {
		return "", errors.New("connections API secret is too large")
	}
	secret := strings.TrimSpace(string(data))
	clear(data)
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return "", errors.New("connections API secret is invalid")
	}
	clear(decoded)
	return secret, nil
}
