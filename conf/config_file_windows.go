//go:build windows

package conf

import (
	"fmt"
	"os"
)

func openSecureConfigFile(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("config must be a regular file")
	}
	return os.Open(path)
}
