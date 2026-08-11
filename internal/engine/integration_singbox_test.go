package engine

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSingBoxOfficialBinary(t *testing.T) {
	binary := os.Getenv("V3NODE_TEST_SING_BOX")
	if binary == "" {
		t.Skip("V3NODE_TEST_SING_BOX is not set")
	}
	certPath, keyPath := testCertificate(t)
	credential := "48e90e76-2a72-46be-ac91-45d96486977a"
	serverKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := []NodeSpec{
		{Protocol: "vmess", Listen: "127.0.0.1", Port: 20001, Transport: "tcp", TLS: TLSSpec{Mode: "none"}},
		{
			Protocol: "vless", Listen: "127.0.0.1", Port: 20002, Transport: "tcp",
			TLS: TLSSpec{
				Mode: "reality", ServerName: "www.example.com",
				DestinationHost: "www.example.com", DestinationPort: 443,
				PrivateKey: "YH_3NR-KMAo_6CQQrwq7YkL_IWBiAlX3MTEaJpDEFTU", ShortIDs: []string{"01234567"},
			},
		},
		{
			Protocol: "trojan", Listen: "127.0.0.1", Port: 20003, Transport: "tcp",
			TLS: TLSSpec{Mode: "tls", ServerName: "example.test", CertificateFile: certPath, KeyFile: keyPath},
		},
		{
			Protocol: "shadowsocks", Listen: "127.0.0.1", Port: 20004, Transport: "tcp",
			Cipher: "2022-blake3-aes-256-gcm", ServerKey: serverKey, TLS: TLSSpec{Mode: "none"},
		},
		{
			Protocol: "shadowsocks", Listen: "127.0.0.1", Port: 20008, Transport: "tcp",
			Cipher: "aes-128-gcm", TLS: TLSSpec{Mode: "none"},
		},
		{
			Protocol: "hysteria2", Listen: "127.0.0.1", Port: 20005, Transport: "tcp",
			UpMbps: 100, DownMbps: 100,
			TLS: TLSSpec{Mode: "tls", ServerName: "example.test", CertificateFile: certPath, KeyFile: keyPath},
		},
		{
			Protocol: "tuic", Listen: "127.0.0.1", Port: 20006, Transport: "tcp",
			CongestionControl: "bbr",
			TLS:               TLSSpec{Mode: "tls", ServerName: "example.test", CertificateFile: certPath, KeyFile: keyPath},
		},
		{
			Protocol: "anytls", Listen: "127.0.0.1", Port: 20007, Transport: "tcp",
			TLS: TLSSpec{Mode: "tls", ServerName: "example.test", CertificateFile: certPath, KeyFile: keyPath},
		},
	}
	for _, node := range cases {
		t.Run(node.Protocol, func(t *testing.T) {
			opts := baseOptions()
			if node.Protocol == "vmess" {
				opts.DNSServers = []string{"tls://dns.example:8853", "https://dns.example/custom-query"}
			}
			user := UserSpec{ID: 9, Credential: credential}
			if node.Protocol == "vmess" {
				user.SpeedLimit = 10
			}
			rendered, err := (SingBoxRenderer{}).Render(node, []UserSpec{user}, opts)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "engine.json")
			if err := os.WriteFile(path, rendered.Config, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(binary, "check", "-c", path)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("sing-box check failed: %v\n%s\nconfig:\n%s", err, output, rendered.Config)
			}
		})
	}
}

func TestSingBoxBlocksPrivateHostname(t *testing.T) {
	binary := os.Getenv("V3NODE_TEST_SING_BOX")
	if binary == "" {
		t.Skip("V3NODE_TEST_SING_BOX is not set")
	}
	ports := freeTCPPorts(t, 4)
	serverPort, statsPort, clashPort, clientPort := ports[0], ports[1], ports[2], ports[3]
	opts := Options{
		LogLevel:        "error",
		StatsListen:     net.JoinHostPort("127.0.0.1", strconv.Itoa(statsPort)),
		ClashListen:     net.JoinHostPort("127.0.0.1", strconv.Itoa(clashPort)),
		ClashSecret:     "private-hostname-integration-secret",
		AddressStrategy: "prefer_ipv4",
		BlockPrivate:    true,
	}
	node := NodeSpec{
		Protocol: "vless", Listen: "127.0.0.1", Port: uint16(serverPort),
		Transport: "tcp", TLS: TLSSpec{Mode: "none"},
	}
	rendered, err := (SingBoxRenderer{}).Render(node, []UserSpec{{ID: 9, Credential: integrationCredential}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	server := startTestEngine(t, "sing-box", binary, rendered.Config)
	defer server.stop(t)
	waitForEnginePort(t, server, net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)))

	client := startTestEngine(t, "sing-box", binary, integrationClientConfig(t, "sing-box", clientPort, serverPort))
	defer client.stop(t)
	waitForEnginePort(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)))

	echoAddress, closeEcho := startEchoServer(t)
	defer closeEcho()
	_, echoPortText, err := net.SplitHostPort(echoAddress)
	if err != nil {
		t.Fatal(err)
	}
	echoPort, err := strconv.Atoi(echoPortText)
	if err != nil {
		t.Fatal(err)
	}
	connection, connectErr := socks5DomainConnect(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)),
		"localhost",
		echoPort,
	)
	if connectErr == nil {
		defer connection.Close()
		payload := []byte("private-hostname-must-not-reach-loopback")
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		_, writeErr := connection.Write(payload)
		received := make([]byte, len(payload))
		_, readErr := io.ReadFull(connection, received)
		if writeErr == nil && readErr == nil && string(received) == string(payload) {
			t.Fatalf("block_private allowed hostname localhost to reach a loopback service\nserver:\n%s\nclient:\n%s", server.output.String(), client.output.String())
		}
	}
	for name, process := range map[string]*testEngineProcess{"server": server, "client": client} {
		select {
		case processErr := <-process.done:
			process.done <- processErr
			t.Fatalf("%s engine exited while testing private-hostname rejection: %v\n%s", name, processErr, process.output.String())
		default:
		}
	}
}

func TestSingBoxProtectsLocalManagementAPI(t *testing.T) {
	binary := os.Getenv("V3NODE_TEST_SING_BOX")
	if binary == "" {
		t.Skip("V3NODE_TEST_SING_BOX is not set")
	}
	ports := freeTCPPorts(t, 4)
	serverPort, statsPort, clashPort, clientPort := ports[0], ports[1], ports[2], ports[3]
	const secret = "management-api-integration-secret"
	opts := Options{
		LogLevel:        "error",
		StatsListen:     net.JoinHostPort("127.0.0.1", strconv.Itoa(statsPort)),
		ClashListen:     net.JoinHostPort("127.0.0.1", strconv.Itoa(clashPort)),
		ClashSecret:     secret,
		AddressStrategy: "prefer_ipv4",
		BlockPrivate:    false,
	}
	node := NodeSpec{
		Protocol: "vless", Listen: "127.0.0.1", Port: uint16(serverPort),
		Transport: "tcp", TLS: TLSSpec{Mode: "none"},
	}
	rendered, err := (SingBoxRenderer{}).Render(node, []UserSpec{{ID: 9, Credential: integrationCredential}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	server := startTestEngine(t, "sing-box", binary, rendered.Config)
	defer server.stop(t)
	waitForEnginePort(t, server, net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)))
	waitForEnginePort(t, server, opts.ClashListen)

	unauthenticated := &http.Client{Timeout: 2 * time.Second}
	response, err := unauthenticated.Get("http://" + opts.ClashListen + "/connections")
	if err != nil {
		t.Fatalf("query Clash API without secret: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Clash API without secret returned HTTP %d, want 401", response.StatusCode)
	}
	connections, err := NewConnectionsClient(opts.ClashListen, 2*time.Second, 10, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connections.Snapshot(context.Background()); err != nil {
		t.Fatalf("query Clash API with secret: %v", err)
	}

	client := startTestEngine(t, "sing-box", binary, integrationClientConfig(t, "sing-box", clientPort, serverPort))
	defer client.stop(t)
	waitForEnginePort(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)))
	connection, connectErr := socks5DomainConnect(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)),
		"localhost",
		clashPort,
	)
	if connectErr == nil {
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		request, err := http.NewRequest(http.MethodGet, "http://localhost/connections", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+secret)
		if err := request.Write(connection); err == nil {
			if response, readErr := http.ReadResponse(bufio.NewReader(connection), request); readErr == nil {
				_ = response.Body.Close()
				t.Fatalf("VPN user reached the loopback management API while block_private=false (HTTP %d)", response.StatusCode)
			}
		}
	}
}

func socks5DomainConnect(proxyAddress, host string, port int) (net.Conn, error) {
	if len(host) == 0 || len(host) > 255 || port < 1 || port > 65535 {
		return nil, errors.New("invalid SOCKS domain target")
	}
	connection, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fail(err)
	}
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(connection, greeting); err != nil {
		return fail(err)
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		return fail(fmt.Errorf("unexpected SOCKS greeting response %v", greeting))
	}
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := connection.Write(request); err != nil {
		return fail(err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return fail(err)
	}
	if header[0] != 5 {
		return fail(fmt.Errorf("unexpected SOCKS version %d", header[0]))
	}
	if header[1] != 0 {
		return fail(fmt.Errorf("SOCKS proxy rejected domain target with code %d", header[1]))
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	return connection, nil
}

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certPath := filepath.Join(directory, "cert.pem")
	keyPath := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
