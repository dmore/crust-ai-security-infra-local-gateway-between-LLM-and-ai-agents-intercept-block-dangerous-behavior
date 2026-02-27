package jsonrpc

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

// PipeConfig describes one direction of the proxy pipeline.
type PipeConfig struct {
	// Label for log messages (e.g., "IDE->Agent", "Client->Server").
	Label string
	// Protocol name for block/log messages ("ACP" or "MCP").
	Protocol string
	// Convert is the method converter. If nil, this direction is passthrough-only.
	Convert MethodConverter
}

// ProxyConfig describes how to run the stdio proxy.
type ProxyConfig struct {
	// Log is the logger to use. Each caller passes its own prefixed logger.
	Log *logger.Logger
	// ProcessLabel is the human name for the child process (e.g., "Agent", "MCP server").
	ProcessLabel string
	// Inbound describes client/IDE -> subprocess direction.
	Inbound PipeConfig
	// Outbound describes subprocess -> client/IDE direction.
	Outbound PipeConfig
	// ExtraLogLines are additional log lines to emit at startup.
	ExtraLogLines []string
}

// RunProxy starts the stdio proxy. It spawns cmd, wires up stdio pipes,
// runs the configured inspection/passthrough pipes, and returns the child's exit code.
func RunProxy(engine *rules.Engine, cmd []string, stdin io.ReadCloser, stdout io.Writer, cfg ProxyConfig) int {
	log := cfg.Log
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	child := exec.CommandContext(ctx, cmd[0], cmd[1:]...) //nolint:gosec // user-specified by design
	childStdin, err := child.StdinPipe()
	if err != nil {
		log.Error("Failed to create %s stdin pipe: %v", cfg.ProcessLabel, err)
		return 1
	}
	childStdout, err := child.StdoutPipe()
	if err != nil {
		childStdin.Close() // Bug fix #4: close already-created pipe
		log.Error("Failed to create %s stdout pipe: %v", cfg.ProcessLabel, err)
		return 1
	}
	child.Stderr = os.Stderr

	if err := child.Start(); err != nil {
		childStdin.Close()
		childStdout.Close()
		log.Error("Failed to start %s: %v", cfg.ProcessLabel, err)
		return 1
	}

	log.Info("%s started: PID %d, command: %v", cfg.ProcessLabel, child.Process.Pid, cmd)
	log.Info("Rule engine: %d rules loaded", engine.RuleCount())
	for _, line := range cfg.ExtraLogLines {
		log.Info("%s", line)
	}

	clientWriter := NewLockedWriter(stdout)
	childWriter := NewLockedWriter(childStdin)

	var wg sync.WaitGroup

	// Goroutine 1: Inbound (client/IDE -> child subprocess)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer childStdin.Close()
		if cfg.Inbound.Convert != nil {
			PipeInspect(log, engine, stdin, childWriter, clientWriter,
				cfg.Inbound.Convert, cfg.Inbound.Protocol, cfg.Inbound.Label)
		} else {
			PipePassthrough(log, stdin, childWriter, cfg.Inbound.Label)
		}
	}()

	// Goroutine 2: Outbound (child subprocess -> client/IDE)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if cfg.Outbound.Convert != nil {
			PipeInspect(log, engine, childStdout, clientWriter, childWriter,
				cfg.Outbound.Convert, cfg.Outbound.Protocol, cfg.Outbound.Label)
		} else {
			PipePassthrough(log, childStdout, clientWriter, cfg.Outbound.Label)
		}
	}()

	// Goroutine 3: Forward signals to child
	// Bug fix #2: signal goroutine tracked in WaitGroup
	sigCh := ForwardSignals()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for sig := range sigCh {
			if child.Process != nil {
				if err := child.Process.Signal(sig); err != nil {
					log.Debug("Signal %v to %s: %v", sig, cfg.ProcessLabel, err)
				}
			}
		}
	}()

	waitErr := child.Wait()
	StopSignals(sigCh)
	cancel()

	// Close client stdin to unblock the inbound goroutine's scanner.
	if stdin != nil {
		if err := stdin.Close(); err != nil {
			log.Debug("Close stdin: %v", err)
		}
	}

	wg.Wait()

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}
