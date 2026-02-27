//go:build !windows

package jsonrpc

import (
	"os"
	"os/signal"
	"syscall"
)

// ForwardSignals registers for SIGINT, SIGTERM, and SIGHUP and returns the channel.
func ForwardSignals() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return ch
}

// StopSignals deregisters and closes the signal channel.
func StopSignals(ch chan os.Signal) {
	signal.Stop(ch)
	close(ch)
}
