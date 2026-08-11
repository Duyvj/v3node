// Command linked_vendor creates a deterministic vendor tree containing the
// dependency source needed by the exact Linux binaries and patch tests shipped
// by v3node. Unlike `go mod vendor`, it does not copy optional sing-box feature
// modules which are not enabled by the release build tags.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type moduleKey struct {
	Path    string
	Version string
}

type moduleInfo struct {
	Path      string      `json:"Path"`
	Version   string      `json:"Version"`
	Dir       string      `json:"Dir"`
	GoMod     string      `json:"GoMod"`
	GoVersion string      `json:"GoVersion"`
	Main      bool        `json:"Main"`
	Replace   *moduleInfo `json:"Replace"`
}

type packageInfo struct {
	Dir        string      `json:"Dir"`
	ImportPath string      `json:"ImportPath"`
	Standard   bool        `json:"Standard"`
	Module     *moduleInfo `json:"Module"`
}

type moduleEdit struct {
	Module struct {
		Path string `json:"Path"`
	} `json:"Module"`
	Go      string `json:"Go"`
	Require []struct {
		Path    string `json:"Path"`
		Version string `json:"Version"`
	} `json:"Require"`
	Replace []json.RawMessage `json:"Replace"`
}

type moduleRecord struct {
	Info     moduleInfo
	Explicit bool
	Packages map[string]string // import path -> source directory
}

type listTarget struct {
	GOARCH   string
	WithTest bool
	Patterns []string
}

var metadataPrefixes = []string{
	"AUTHORS", "CONTRIBUTORS", "COPYLEFT", "COPYING", "COPYRIGHT",
	"LEGAL", "LICENSE", "NOTICE", "PATENTS",
}

func main() {
	var sourceDirectory string
	var tags string
	var goBinary string
	flag.StringVar(&sourceDirectory, "source", "", "patched sing-box source directory")
	flag.StringVar(&tags, "tags", "", "comma-separated release build tags")
	flag.StringVar(&goBinary, "go", "go", "Go command to invoke")
	flag.Parse()
	if flag.NArg() != 0 || sourceDirectory == "" || tags == "" {
		fatalf("usage: linked_vendor --source DIR --tags TAGS [--go PATH]")
	}

	absoluteSource, err := filepath.Abs(sourceDirectory)
	if err != nil {
		fatalf("resolve source directory: %v", err)
	}
	if info, err := os.Stat(filepath.Join(absoluteSource, "go.mod")); err != nil || !info.Mode().IsRegular() {
		fatalf("source directory has no regular go.mod")
	}
	vendorDirectory := filepath.Join(absoluteSource, "vendor")
	if _, err := os.Lstat(vendorDirectory); err == nil {
		fatalf("vendor directory already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		fatalf("inspect vendor directory: %v", err)
	}

	editBytes, err := runGo(absoluteSource, goBinary, nil, "mod", "edit", "-json")
	if err != nil {
		fatalf("read go.mod: %v", err)
	}
	var edit moduleEdit
	if err := json.Unmarshal(editBytes, &edit); err != nil {
		fatalf("decode go.mod metadata: %v", err)
	}
	if edit.Module.Path != "github.com/sagernet/sing-box" {
		fatalf("unexpected module path %q", edit.Module.Path)
	}
	if len(edit.Replace) != 0 {
		fatalf("module replacements are not supported by the linked-source vendor builder")
	}

	records := make(map[moduleKey]*moduleRecord)
	for _, requirement := range edit.Require {
		key := moduleKey{Path: requirement.Path, Version: requirement.Version}
		records[key] = &moduleRecord{
			Info:     moduleInfo{Path: requirement.Path, Version: requirement.Version},
			Explicit: true,
			Packages: make(map[string]string),
		}
	}

	targets := []listTarget{
		{GOARCH: "amd64", Patterns: []string{"./cmd/sing-box"}},
		{GOARCH: "arm64", Patterns: []string{"./cmd/sing-box"}},
		{
			GOARCH:   "amd64",
			WithTest: true,
			Patterns: []string{"./experimental/clashapi/trafficontrol", "./experimental/v3node"},
		},
	}
	for _, target := range targets {
		if err := collectPackages(absoluteSource, goBinary, tags, target, edit.Module.Path, records); err != nil {
			fatalf("collect linux/%s dependency source: %v", target.GOARCH, err)
		}
	}

	keys := sortedModuleKeys(records)
	for _, key := range keys {
		record := records[key]
		packagePaths := sortedPackagePaths(record.Packages)
		for _, packagePath := range packagePaths {
			if err := copyPackageTree(
				vendorDirectory,
				record.Info,
				packagePath,
				record.Packages[packagePath],
			); err != nil {
				fatalf("vendor %s: %v", packagePath, err)
			}
		}
	}
	if err := writeModulesFile(vendorDirectory, keys, records); err != nil {
		fatalf("write vendor/modules.txt: %v", err)
	}
	fmt.Printf("linked vendor contains %d modules and %d packages\n", countUsedModules(records), countPackages(records))
}

func collectPackages(sourceDirectory, goBinary, tags string, target listTarget, mainModule string, records map[moduleKey]*moduleRecord) error {
	arguments := []string{"list", "-mod=readonly", "-tags", tags, "-deps"}
	if target.WithTest {
		arguments = append(arguments, "-test")
	}
	arguments = append(arguments, "-json")
	arguments = append(arguments, target.Patterns...)
	output, err := runGo(sourceDirectory, goBinary, map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        "linux",
		"GOARCH":      target.GOARCH,
		"GOTOOLCHAIN": "local",
	}, arguments...)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var current packageInfo
		if err := decoder.Decode(&current); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("decode go list output: %w", err)
		}
		if current.Standard || current.Module == nil || current.Module.Main || current.Module.Path == mainModule || current.Dir == "" {
			continue
		}
		if strings.Contains(current.ImportPath, " [") || strings.HasSuffix(current.ImportPath, ".test") {
			continue
		}
		module := *current.Module
		if module.Replace != nil {
			return fmt.Errorf("package %s uses unsupported module replacement", current.ImportPath)
		}
		if !validImportPath(module.Path) || !validImportPath(current.ImportPath) ||
			(current.ImportPath != module.Path && !strings.HasPrefix(current.ImportPath, module.Path+"/")) {
			return fmt.Errorf("package %q is outside module %q", current.ImportPath, module.Path)
		}
		if module.Dir == "" {
			return fmt.Errorf("module %s@%s has no source directory", module.Path, module.Version)
		}
		key := moduleKey{Path: module.Path, Version: module.Version}
		record := records[key]
		if record == nil {
			record = &moduleRecord{Info: module, Packages: make(map[string]string)}
			records[key] = record
		} else {
			if record.Info.Dir != "" && !samePath(record.Info.Dir, module.Dir) {
				return fmt.Errorf("module %s@%s resolved to multiple directories", module.Path, module.Version)
			}
			record.Info = mergeModuleInfo(record.Info, module)
		}
		if existing := record.Packages[current.ImportPath]; existing != "" && !samePath(existing, current.Dir) {
			return fmt.Errorf("package %s resolved to multiple directories", current.ImportPath)
		}
		record.Packages[current.ImportPath] = current.Dir
	}
	return nil
}

func mergeModuleInfo(current, next moduleInfo) moduleInfo {
	if current.Path == "" {
		current.Path = next.Path
	}
	if current.Version == "" {
		current.Version = next.Version
	}
	if current.Dir == "" {
		current.Dir = next.Dir
	}
	if current.GoMod == "" {
		current.GoMod = next.GoMod
	}
	if current.GoVersion == "" {
		current.GoVersion = next.GoVersion
	}
	return current
}

func copyPackageTree(vendorDirectory string, module moduleInfo, packagePath, source string) error {
	moduleRoot, err := filepath.Abs(module.Dir)
	if err != nil {
		return err
	}
	packageRoot, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	inside, err := filepath.Rel(moduleRoot, packageRoot)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return fmt.Errorf("source directory is outside its module root")
	}
	destination := filepath.Join(vendorDirectory, filepath.FromSlash(packagePath))
	if err := copyTree(packageRoot, destination); err != nil {
		return err
	}
	return copyMetadataParents(vendorDirectory, module.Path, packagePath, moduleRoot, packageRoot)
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if relative != "." && (entry.Name() == ".git" || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source contains unsupported symlink %s", current)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if entry.Name() == "go.mod" || entry.Name() == "go.sum" {
			return nil
		}
		return copyRegularFile(current, filepath.Join(destination, relative))
	})
}

func copyMetadataParents(vendorDirectory, modulePath, packagePath, moduleRoot, packageRoot string) error {
	currentSource := packageRoot
	currentPackage := packagePath
	for {
		entries, err := os.ReadDir(currentSource)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() || !entry.Type().IsRegular() || !isMetadataName(entry.Name()) {
				continue
			}
			destination := filepath.Join(vendorDirectory, filepath.FromSlash(currentPackage), entry.Name())
			if err := copyRegularFile(filepath.Join(currentSource, entry.Name()), destination); err != nil {
				return err
			}
		}
		if samePath(currentSource, moduleRoot) || currentPackage == modulePath {
			return nil
		}
		parent := filepath.Dir(currentSource)
		if parent == currentSource {
			return fmt.Errorf("reached filesystem root before module root")
		}
		currentSource = parent
		currentPackage = path.Dir(currentPackage)
	}
}

func copyRegularFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if existing, err := os.Open(destination); err == nil {
		defer existing.Close()
		equal, compareErr := streamsEqual(input, existing)
		if compareErr != nil {
			return compareErr
		}
		if !equal {
			return fmt.Errorf("conflicting destination %s", destination)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}

func streamsEqual(left, right io.Reader) (bool, error) {
	leftBytes, err := io.ReadAll(left)
	if err != nil {
		return false, err
	}
	rightBytes, err := io.ReadAll(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftBytes, rightBytes), nil
}

func writeModulesFile(vendorDirectory string, keys []moduleKey, records map[moduleKey]*moduleRecord) error {
	var output strings.Builder
	for _, key := range keys {
		record := records[key]
		fmt.Fprintf(&output, "# %s %s\n", key.Path, key.Version)
		switch {
		case record.Explicit && record.Info.GoVersion != "":
			fmt.Fprintf(&output, "## explicit; go %s\n", record.Info.GoVersion)
		case record.Explicit:
			output.WriteString("## explicit\n")
		case record.Info.GoVersion != "":
			fmt.Fprintf(&output, "## go %s\n", record.Info.GoVersion)
		}
		for _, packagePath := range sortedPackagePaths(record.Packages) {
			fmt.Fprintln(&output, packagePath)
		}
	}
	if err := os.MkdirAll(vendorDirectory, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(vendorDirectory, "modules.txt"), []byte(output.String()), 0o644)
}

func runGo(directory, binary string, extraEnvironment map[string]string, arguments ...string) ([]byte, error) {
	command := exec.Command(binary, arguments...)
	command.Dir = directory
	command.Env = mergedEnvironment(os.Environ(), extraEnvironment)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("%w: %s", err, message)
		}
		return nil, err
	}
	return output, nil
}

func mergedEnvironment(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return base
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, value := range base {
		key, _, found := strings.Cut(value, "=")
		if found {
			if _, overridden := overrides[strings.ToUpper(key)]; overridden {
				continue
			}
		}
		result = append(result, value)
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+overrides[key])
	}
	return result
}

func sortedModuleKeys(records map[moduleKey]*moduleRecord) []moduleKey {
	keys := make([]moduleKey, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Path == keys[j].Path {
			return keys[i].Version < keys[j].Version
		}
		return keys[i].Path < keys[j].Path
	})
	return keys
}

func sortedPackagePaths(packages map[string]string) []string {
	result := make([]string, 0, len(packages))
	for packagePath := range packages {
		result = append(result, packagePath)
	}
	sort.Strings(result)
	return result
}

func validImportPath(value string) bool {
	return value != "" && value == path.Clean(value) && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && !strings.Contains(value, "..")
}

func isMetadataName(name string) bool {
	for _, prefix := range metadataPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func samePath(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	if strings.EqualFold(leftAbsolute, rightAbsolute) {
		return true
	}
	return leftAbsolute == rightAbsolute
}

func countUsedModules(records map[moduleKey]*moduleRecord) int {
	count := 0
	for _, record := range records {
		if len(record.Packages) > 0 {
			count++
		}
	}
	return count
}

func countPackages(records map[moduleKey]*moduleRecord) int {
	count := 0
	for _, record := range records {
		count += len(record.Packages)
	}
	return count
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "linked_vendor: "+format+"\n", arguments...)
	os.Exit(1)
}
