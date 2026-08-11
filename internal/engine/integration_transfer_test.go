package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const integrationCredential = "48e90e76-2a72-46be-ac91-45d96486977a"

func TestSingBoxVLESSDataTransfer(t *testing.T) {
	binaryPath := os.Getenv("V3NODE_TEST_SING_BOX")
	if binaryPath == "" {
		t.Skip("V3NODE_TEST_SING_BOX is not set")
	}
	testVLESSDataTransfer(t, "sing-box", binaryPath)
}

func TestXrayVLESSDataTransfer(t *testing.T) {
	binaryPath := os.Getenv("V3NODE_TEST_XRAY")
	if binaryPath == "" {
		t.Skip("V3NODE_TEST_XRAY is not set")
	}
	testVLESSDataTransfer(t, "xray", binaryPath)
}

func testVLESSDataTransfer(t *testing.T, backend, binaryPath string) {
	t.Helper()
	ports := freeTCPPorts(t, 4)
	serverPort, statsPort, clashPort, clientPort := ports[0], ports[1], ports[2], ports[3]

	node := NodeSpec{
		Protocol:  "vless",
		Listen:    "127.0.0.1",
		Port:      uint16(serverPort),
		Transport: "tcp",
		TLS:       TLSSpec{Mode: "none"},
	}
	opts := Options{
		LogLevel:        "error",
		StatsListen:     net.JoinHostPort("127.0.0.1", fmt.Sprint(statsPort)),
		ClashListen:     net.JoinHostPort("127.0.0.1", fmt.Sprint(clashPort)),
		ClashSecret:     "integration-test-connections-secret",
		AddressStrategy: "prefer_ipv4",
		BlockPrivate:    false,
	}

	var renderer Renderer
	if backend == "sing-box" {
		renderer = SingBoxRenderer{}
	} else {
		renderer = XrayRenderer{}
	}
	rendered, err := renderer.Render(node, []UserSpec{{ID: 9, Credential: integrationCredential}}, opts)
	if err != nil {
		t.Fatal(err)
	}

	server := startTestEngine(t, backend, binaryPath, rendered.Config)
	defer server.stop(t)
	waitForEnginePort(t, server, net.JoinHostPort("127.0.0.1", fmt.Sprint(serverPort)))

	clientConfig := integrationClientConfig(t, backend, clientPort, serverPort)
	client := startTestEngine(t, backend, binaryPath, clientConfig)
	defer client.stop(t)
	waitForEnginePort(t, client, net.JoinHostPort("127.0.0.1", fmt.Sprint(clientPort)))

	echoAddress, closeEcho := startEchoServer(t)
	defer closeEcho()
	connection := dialSOCKS5(t, net.JoinHostPort("127.0.0.1", fmt.Sprint(clientPort)), echoAddress)
	defer connection.Close()

	payload := bytes.Repeat([]byte("v3node-transfer-check-"), 1024)
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(payload); err != nil {
		t.Fatalf("write through VLESS tunnel: %v", err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatalf("read through VLESS tunnel: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("VLESS tunnel changed the transferred payload")
	}

	stats, err := NewStatsClient(opts.StatsListen, 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer stats.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		sample, pollErr := stats.Poll(context.Background(), 1, rendered.Users)
		if pollErr == nil {
			if delta := sample.Deltas[9]; delta.Upload > 0 && delta.Download > 0 {
				return
			}
		}
		if time.Now().After(deadline) {
			if pollErr != nil {
				t.Fatalf("traffic did not reach the stats API: %v", pollErr)
			}
			t.Fatal("traffic did not appear in both per-user counters")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func integrationClientConfig(t *testing.T, backend string, clientPort, serverPort int) []byte {
	t.Helper()
	var document map[string]any
	if backend == "sing-box" {
		document = map[string]any{
			"log": map[string]any{"level": "error"},
			"inbounds": []any{map[string]any{
				"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": clientPort,
			}},
			"outbounds": []any{map[string]any{
				"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": serverPort,
				"uuid": integrationCredential,
			}},
			"route": map[string]any{"final": "proxy"},
		}
	} else {
		document = map[string]any{
			"log": map[string]any{"loglevel": "error"},
			"inbounds": []any{map[string]any{
				"listen": "127.0.0.1", "port": clientPort, "protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": false},
			}},
			"outbounds": []any{map[string]any{
				"protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "127.0.0.1", "port": serverPort,
					"users": []any{map[string]any{"id": integrationCredential, "encryption": "none"}},
				}}},
				"streamSettings": map[string]any{"network": "tcp", "security": "none"},
			}},
		}
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type testEngineProcess struct {
	command *exec.Cmd
	done    chan error
	output  *bytes.Buffer
}

func startTestEngine(t *testing.T, backend, binaryPath string, config []byte) *testEngineProcess {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-c", configPath}
	if backend == "xray" {
		args = []string{"run", "-config", configPath}
	}
	output := new(bytes.Buffer)
	command := exec.Command(binaryPath, args...)
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", backend, err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	return &testEngineProcess{command: command, done: done, output: output}
}

func (p *testEngineProcess) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.command.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Errorf("engine did not stop after kill")
	}
}

func waitForEnginePort(t *testing.T, process *testEngineProcess, address string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		select {
		case processErr := <-process.done:
			// Preserve the terminal result for the deferred cleanup path.
			process.done <- processErr
			t.Fatalf("engine exited before listening on %s: %v\n%s", address, processErr, process.output.String())
		default:
		}
		if time.Now().After(deadline) {
			process.stop(t)
			t.Fatalf("engine did not listen on %s\n%s", address, process.output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func freeTCPPorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	ports := make([]int, 0, count)
	for range count {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
	}
}

func dialSOCKS5(t *testing.T, proxyAddress, targetAddress string) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
	if err != nil {
		t.Fatalf("connect to local SOCKS listener: %v", err)
	}
	fail := func(message string, values ...any) {
		_ = connection.Close()
		t.Fatalf(message, values...)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		fail("set SOCKS deadline: %v", err)
	}
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		fail("write SOCKS greeting: %v", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || !bytes.Equal(response, []byte{5, 0}) {
		fail("SOCKS greeting failed: response=%v err=%v", response, err)
	}
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		fail("parse echo address: %v", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		fail("echo server did not use IPv4")
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		fail("parse echo port: %v", err)
	}
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(request[len(request)-2:], uint16(port))
	if _, err := connection.Write(request); err != nil {
		fail("write SOCKS connect request: %v", err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		fail("read SOCKS connect response: %v", err)
	}
	if header[0] != 5 || header[1] != 0 {
		fail("SOCKS proxy rejected connection: %v", header)
	}
	addressLength := 0
	switch header[3] {
	case 1:
		addressLength = 4
	case 4:
		addressLength = 16
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil {
			fail("read SOCKS domain length: %v", err)
		}
		addressLength = int(length[0])
	default:
		fail("SOCKS proxy returned unknown address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, connection, int64(addressLength+2)); err != nil {
		fail("read SOCKS bound address: %v", err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil && !errors.Is(err, net.ErrClosed) {
		fail("clear SOCKS deadline: %v", err)
	}
	return connection
}
