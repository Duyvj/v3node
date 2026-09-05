package cmd

import (
	"os"
	"path/filepath"
)

const xrayAssetLocationEnv = "XRAY_LOCATION_ASSET"

// configureAssetLocation makes geoip:/geosite: routing deterministic for every
// launch mode. Xray otherwise relies on the process working directory, which
// differs between systemd, Docker and manual executions.
func configureAssetLocation(configPath string) string {
	if configured := os.Getenv(xrayAssetLocationEnv); configured != "" {
		return configured
	}

	candidates := []string{filepath.Dir(configPath)}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(executable))
	}
	if workingDirectory, err := os.Getwd(); err == nil {
		candidates = append(candidates, workingDirectory)
	}

	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		if hasGeoData(candidate) {
			_ = os.Setenv(xrayAssetLocationEnv, candidate)
			return candidate
		}
	}
	return ""
}

func hasGeoData(directory string) bool {
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.IsDir() || info.Size() < 1024 {
			return false
		}
	}
	return true
}
