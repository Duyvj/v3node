package engine

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestXrayOfficialBinary(t *testing.T) {
	binary := os.Getenv("V3NODE_TEST_XRAY")
	if binary == "" {
		t.Skip("V3NODE_TEST_XRAY is not set")
	}
	certPath, keyPath := testCertificate(t)
	credential := "48e90e76-2a72-46be-ac91-45d96486977a"
	cases := []NodeSpec{
		{
			Protocol: "vless", Listen: "127.0.0.1", Port: 21000, Transport: "tcp",
			Encryption:         "mlkem768x25519plus",
			EncryptionSettings: json.RawMessage(`{"mode":"native","ticket":"600s","server_padding":"100-111-1111.75-0-111.50-0-3333","private_key":"0B7MUsfiVdKqBK20cdhgsBnJyaz-XXrR3qal7rSVHFM"}`),
			TLS:                TLSSpec{Mode: "none"},
			Routes:             []RouteSpec{{ID: 2, Action: "dns", ActionValue: "1.1.1.1"}},
		},
		{
			Protocol: "vless", Listen: "127.0.0.1", Port: 21006, Transport: "tcp",
			TLS:    TLSSpec{Mode: "none"},
			Routes: []RouteSpec{{ID: 1, Action: "block", Match: []string{"geosite:category-ads-all"}}},
		},
		{
			Protocol: "vless", Listen: "127.0.0.1", Port: 21001, Transport: "xhttp",
			TransportSettings: json.RawMessage("{\"path\":\"/edge\",\"mode\":\"auto\"}"),
			TLS: TLSSpec{
				Mode: "reality", ServerName: "www.example.com", ServerNames: []string{"www.example.com"},
				DestinationHost: "www.example.com", DestinationPort: 443,
				PrivateKey: "YH_3NR-KMAo_6CQQrwq7YkL_IWBiAlX3MTEaJpDEFTU", ShortIDs: []string{"01234567"},
			},
		},
		{
			Protocol: "vmess", Listen: "127.0.0.1", Port: 21002, Transport: "ws",
			TransportSettings: json.RawMessage("{\"path\":\"/ws\"}"),
			TLS:               TLSSpec{Mode: "none"},
		},
		{
			Protocol: "trojan", Listen: "127.0.0.1", Port: 21003, Transport: "tcp",
			TLS: TLSSpec{Mode: "tls", ServerName: "example.test", CertificateFile: certPath, KeyFile: keyPath},
		},
		{
			Protocol: "shadowsocks", Listen: "127.0.0.1", Port: 21004, Transport: "tcp",
			Cipher: "aes-128-gcm", TransportSettings: json.RawMessage(`{"path":"/edge","Host":"cdn.example"}`), TLS: TLSSpec{Mode: "none"},
		},
		{
			Protocol: "shadowsocks", Listen: "127.0.0.1", Port: 21005, Transport: "tcp",
			Cipher: "2022-blake3-aes-256-gcm", ServerKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TLS: TLSSpec{Mode: "none"},
		},
		{
			Protocol: "vless", Listen: "127.0.0.1", Port: 21007, Transport: "tcp", TLS: TLSSpec{Mode: "none"},
			Routes: []RouteSpec{{
				ID: 7, Action: "route", Match: []string{"domain:example.com"},
				ActionValue: `{"tag":"regional","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}}`,
			}},
		},
	}
	for _, node := range cases {
		t.Run(node.Protocol+"-"+node.Transport, func(t *testing.T) {
			rendered, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 9, Credential: credential}}, baseOptions())
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "engine.json")
			if err := os.WriteFile(path, rendered.Config, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(binary, "run", "-test", "-config", path)
			command.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(binary))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("Xray check failed: %v\n%s\nconfig:\n%s", err, output, rendered.Config)
			}
		})
	}
}

func TestXrayProtectsLocalManagementAPI(t *testing.T) {
	binary := os.Getenv("V3NODE_TEST_XRAY")
	if binary == "" {
		t.Skip("V3NODE_TEST_XRAY is not set")
	}
	ports := freeTCPPorts(t, 4)
	serverPort, statsPort, clashPort, clientPort := ports[0], ports[1], ports[2], ports[3]
	opts := Options{
		LogLevel:        "error",
		StatsListen:     net.JoinHostPort("127.0.0.1", strconv.Itoa(statsPort)),
		ClashListen:     net.JoinHostPort("127.0.0.1", strconv.Itoa(clashPort)),
		ClashSecret:     "xray-management-integration-secret",
		AddressStrategy: "prefer_ipv4",
		BlockPrivate:    false,
	}
	node := NodeSpec{
		Protocol: "vless", Listen: "127.0.0.1", Port: uint16(serverPort),
		Transport: "tcp", TLS: TLSSpec{Mode: "none"},
	}
	rendered, err := (XrayRenderer{}).Render(node, []UserSpec{{ID: 9, Credential: integrationCredential}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	server := startTestEngine(t, "xray", binary, rendered.Config)
	defer server.stop(t)
	waitForEnginePort(t, server, net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)))
	waitForEnginePort(t, server, opts.StatsListen)
	management, err := net.DialTimeout("tcp", opts.StatsListen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = management.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := management.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		_ = management.Close()
		t.Fatal(err)
	}
	if _, err := io.ReadFull(management, make([]byte, 9)); err != nil {
		_ = management.Close()
		t.Fatalf("direct management API control connection failed: %v", err)
	}
	_ = management.Close()

	client := startTestEngine(t, "xray", binary, integrationClientConfig(t, "xray", clientPort, serverPort))
	defer client.stop(t)
	waitForEnginePort(t, client, net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)))
	connection, connectErr := socks5DomainConnect(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort)),
		"localhost",
		statsPort,
	)
	if connectErr == nil {
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		_, writeErr := connection.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
		frameHeader := make([]byte, 9)
		_, readErr := io.ReadFull(connection, frameHeader)
		if writeErr == nil && readErr == nil {
			t.Fatalf("VPN user reached the Xray loopback management API while block_private=false\nserver:\n%s\nclient:\n%s\nconfig:\n%s", server.output.String(), client.output.String(), rendered.Config)
		}
	}
}
