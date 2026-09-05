package conf

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const maxRedisCAFileBytes = 1 << 20

// RedisTLSConfig is shared by the limiter and Pub/Sub clients. Plaintext TCP
// is allowed only on numeric loopback so credentials and device identifiers
// never cross a shared network in clear text.
func RedisTLSConfig(config *GlobalDeviceLimitConfig) (*tls.Config, error) {
	if config == nil || !config.Enable {
		return nil, nil
	}
	network := strings.ToLower(strings.TrimSpace(config.RedisNetwork))
	if network == "" {
		network = "tcp"
	}
	if network == "unix" {
		if config.RedisTLS {
			return nil, fmt.Errorf("RedisTLS cannot be used with a unix socket")
		}
		return nil, nil
	}
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported Redis network %q", config.RedisNetwork)
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(config.RedisAddr))
	if err != nil {
		return nil, fmt.Errorf("RedisAddr must be host:port: %w", err)
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return nil, fmt.Errorf("RedisAddr host is empty")
	}
	if !config.RedisTLS {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("Redis TCP outside numeric loopback requires RedisTLS=true")
		}
		return nil, nil
	}
	if len(config.RedisSentinelAddrs) > 64 {
		return nil, fmt.Errorf("RedisSentinelAddrs contains too many addresses")
	}
	for _, address := range config.RedisSentinelAddrs {
		sentinelHost, _, splitErr := net.SplitHostPort(strings.TrimSpace(address))
		if splitErr != nil || strings.Trim(strings.TrimSpace(sentinelHost), "[]") == "" {
			return nil, fmt.Errorf("Redis sentinel address %q must be host:port", address)
		}
	}

	serverName := strings.TrimSpace(config.RedisTLSServerName)
	if serverName == "" {
		serverName = host
	}
	if strings.ContainsAny(serverName, "\x00\r\n\t /\\") {
		return nil, fmt.Errorf("RedisTLSServerName is invalid")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}

	caFile := strings.TrimSpace(config.RedisTLSCAFile)
	inlineCA := strings.TrimSpace(config.RedisTLSCACert)
	if caFile == "" && inlineCA == "" {
		return tlsConfig, nil
	}
	var pem []byte
	if inlineCA != "" {
		pem = []byte(inlineCA)
		if len(pem) > maxRedisCAFileBytes {
			return nil, fmt.Errorf("inline Redis TLS CA is larger than %d bytes", maxRedisCAFileBytes)
		}
	} else {
		file, err := os.Open(caFile)
		if err != nil {
			return nil, fmt.Errorf("open Redis TLS CA file: %w", err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxRedisCAFileBytes {
			return nil, fmt.Errorf("Redis TLS CA file must be a regular file no larger than %d bytes", maxRedisCAFileBytes)
		}
		pem, err = io.ReadAll(io.LimitReader(file, maxRedisCAFileBytes+1))
		if err != nil || len(pem) > maxRedisCAFileBytes {
			return nil, fmt.Errorf("read Redis TLS CA file")
		}
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("Redis TLS CA contains no valid certificate")
	}
	tlsConfig.RootCAs = pool
	return tlsConfig, nil
}
