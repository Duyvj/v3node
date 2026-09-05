package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/go-resty/resty/v2"
)

const defaultInstanceSecretPath = "/etc/znode/instance-secret"

var (
	identityOnce sync.Once
	identityID   string
	addressOnce  sync.Once
	hostIPv4     string
	hostIPv6     string
)

func effectiveInstanceID(configured string) string {
	if value := strings.TrimSpace(configured); value != "" {
		return value
	}
	identityOnce.Do(func() {
		seed, _ := os.ReadFile("/etc/machine-id")
		if len(strings.TrimSpace(string(seed))) == 0 {
			hostname, _ := os.Hostname()
			seed = []byte(hostname)
		}
		digest := sha256.Sum256(seed)
		value := hex.EncodeToString(digest[:16])
		identityID = value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
	})
	return identityID
}

func setAddressHeaders(client *resty.Client) {
	addressOnce.Do(discoverHostAddresses)
	if hostIPv4 != "" {
		client.SetHeader("X-ZNode-IPv4", hostIPv4)
	}
	if hostIPv6 != "" {
		client.SetHeader("X-ZNode-IPv6", hostIPv6)
	}
}

func setInstanceSecretHeader(client *resty.Client) string {
	secret := loadInstanceSecret()
	if secret != "" {
		client.SetHeader("X-ZNode-Instance-Secret", secret)
	}
	return secret
}

func loadInstanceSecret() string {
	path := strings.TrimSpace(os.Getenv("ZNODE_INSTANCE_SECRET_FILE"))
	if path == "" {
		path = defaultInstanceSecretPath
	}
	if !filepath.IsAbs(path) {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return ""
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	secret := strings.TrimSpace(string(value))
	decoded, err := hex.DecodeString(secret)
	if err != nil || len(decoded) != 32 || secret != strings.ToLower(secret) {
		return ""
	}
	return secret
}

func discoverHostAddresses() {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip == nil || !ip.IsGlobalUnicast() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			candidate := ipv4.String()
			if hostIPv4 == "" || (isPrivateIP(net.ParseIP(hostIPv4)) && !isPrivateIP(ip)) {
				hostIPv4 = candidate
			}
			continue
		}
		if hostIPv6 == "" && !ip.IsPrivate() {
			hostIPv6 = ip.String()
		}
	}
}

func isPrivateIP(ip net.IP) bool {
	return ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
