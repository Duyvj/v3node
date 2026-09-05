// Package terminal implements the outbound-only ZBoard terminal relay.
package terminal

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/Duyvj/v3node/conf"
	"github.com/creack/pty"
)

const (
	maxChunk         = 32 * 1024
	hardLifetime     = 10 * time.Minute
	idleLifetime     = 2 * time.Minute
	claimInterval    = 500 * time.Millisecond
	maxClaimInterval = 15 * time.Second
	exchangeInterval = 100 * time.Millisecond
)

// Run claims terminal sessions serially until ctx is cancelled. It creates no
// listening socket; every relay operation is an authenticated HTTPS request.
func Run(ctx context.Context, config conf.AgentConfig) error {
	client, err := panel.NewAgentClient(config)
	if err != nil {
		return err
	}
	claimDelay := claimInterval
	for {
		if ctx.Err() != nil {
			return nil
		}
		claim, err := client.ClaimTerminal(ctx)
		if err == nil && claim != nil {
			claimDelay = claimInterval
			_ = runSession(ctx, client, claim)
			continue
		}
		if !wait(ctx, claimDelay) {
			return nil
		}
		claimDelay = nextBackoff(claimDelay, maxClaimInterval)
	}
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum/2 {
		return maximum
	}
	return current * 2
}

func wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func runSession(parent context.Context, client *panel.AgentClient, claim *panel.AgentTerminalSession) error {
	ctx, cancel := context.WithTimeout(parent, hardLifetime)
	defer cancel()
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer closeCancel()
		_ = client.CloseTerminal(closeCtx, claim.ID)
	}()
	ptmx, cmd, err := startPTY()
	if err != nil {
		return err
	}
	defer stopPTY(ptmx, cmd)
	output := make(chan []byte, 1)
	readDone := make(chan struct{})
	go readPTY(ctx, ptmx, output, readDone)
	status := claim.Status
	var lastCols, lastRows string
	var inSeq, outSeq uint64
	var pendingOutput []byte
	var pendingOutputSeq uint64
	lastActivity := time.Now()
	for {
		if time.Since(lastActivity) >= idleLifetime {
			return nil
		}
		if err := resizePTY(ptmx, status, &lastCols, &lastRows); err != nil {
			return err
		}
		if len(pendingOutput) == 0 {
			select {
			case pendingOutput = <-output:
				if len(pendingOutput) > 0 {
					pendingOutputSeq = outSeq + 1
				}
			default:
			}
		}
		var data string
		var sendSeq uint64
		if len(pendingOutput) > 0 {
			sendSeq = pendingOutputSeq
			data = base64.StdEncoding.EncodeToString(pendingOutput)
		}
		exchange, err := client.ExchangeTerminal(ctx, claim.ID, sendSeq, data, inSeq)
		if err != nil {
			if panel.IsTerminalSessionClosed(err) {
				return err
			}
			// A response can be lost after the panel has accepted output or
			// delivered input. Keep both watermarks unchanged and retry; the
			// panel queues are ACK-based and duplicate output sequence numbers are
			// intentionally idempotent.
			if !wait(ctx, exchangeInterval) {
				return nil
			}
			continue
		}
		if len(pendingOutput) > 0 {
			outSeq = pendingOutputSeq
			pendingOutput = nil
			pendingOutputSeq = 0
			lastActivity = time.Now()
		}
		status = exchange.Status
		if relaySessionActive(status, time.Now()) {
			lastActivity = time.Now()
		}
		for _, input := range exchange.Input {
			if input.Seq <= inSeq {
				continue
			}
			if input.Seq != inSeq+1 {
				return fmt.Errorf("terminal input sequence out of order")
			}
			bytes, err := decodeChunk(input.Data)
			if err != nil {
				return err
			}
			if _, err := ptmx.Write(bytes); err != nil {
				return fmt.Errorf("write terminal input: %w", err)
			}
			inSeq = input.Seq
			lastActivity = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-readDone:
			return nil
		default:
		}
		if !wait(ctx, exchangeInterval) {
			return nil
		}
	}
}

func relaySessionActive(status map[string]string, now time.Time) bool {
	lastSeen, err := strconv.ParseInt(status["last_activity"], 10, 64)
	if err != nil || lastSeen <= 0 {
		return false
	}
	activity := time.Unix(lastSeen, 0)
	return !activity.After(now.Add(5*time.Second)) && activity.After(now.Add(-idleLifetime))
}

func decodeChunk(encoded string) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxChunk) {
		return nil, errors.New("terminal input chunk is invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) > maxChunk {
		return nil, errors.New("terminal input chunk is invalid")
	}
	return decoded, nil
}

func readPTY(ctx context.Context, ptmx *os.File, output chan<- []byte, done chan<- struct{}) {
	defer close(done)
	defer close(output)
	buffer := make([]byte, maxChunk)
	for {
		n, err := ptmx.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			select {
			case output <- chunk:
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func shellPath() string {
	shell := "/bin/bash"
	if info, err := os.Stat(shell); err != nil || info.Mode()&0o111 == 0 {
		shell = "/bin/sh"
	}
	return shell
}

func sanitizedEnv() []string {
	return []string{"HOME=/root", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm-256color", "LANG=C"}
}

func startPTY() (*os.File, *exec.Cmd, error) {
	shell := shellPath()
	cmd := exec.Command(shell)
	cmd.Dir = "/root"
	cmd.Env = sanitizedEnv()
	// pty.Start creates a new session/process group. Combining its Setsid with
	// Setpgid can make fork/exec fail on Linux.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("start terminal: %w", err)
	}
	return ptmx, cmd, nil
}

func stopPTY(ptmx *os.File, cmd *exec.Cmd) {
	terminateProcess(cmd)
	if ptmx != nil {
		_ = ptmx.Close()
	}
	if cmd != nil {
		waitDone := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(5 * time.Second):
			forceKillProcess(cmd)
			<-waitDone
		}
	}
}

func resizePTY(ptmx *os.File, status map[string]string, lastCols, lastRows *string) error {
	cols, rows := status["cols"], status["rows"]
	if cols == "" || rows == "" || (cols == *lastCols && rows == *lastRows) {
		return nil
	}
	c, err := strconv.Atoi(cols)
	if err != nil || c < 1 || c > 500 {
		return errors.New("terminal columns are invalid")
	}
	r, err := strconv.Atoi(rows)
	if err != nil || r < 1 || r > 500 {
		return errors.New("terminal rows are invalid")
	}
	if err := pty.Setsize(ptmx, &pty.Winsize{Cols: uint16(c), Rows: uint16(r)}); err != nil {
		return fmt.Errorf("resize terminal: %w", err)
	}
	*lastCols, *lastRows = cols, rows
	return nil
}
