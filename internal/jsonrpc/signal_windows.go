//go:build windows

package jsonrpc

import (
	"os"
	"os/signal"
)

// ForwardSignals registers for os.Interrupt and returns the channel.
func ForwardSignals() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return ch
}

// StopSignals deregisters and closes the signal channel.
func StopSignals(ch chan os.Signal) {
	signal.Stop(ch)
	close(ch)
}
