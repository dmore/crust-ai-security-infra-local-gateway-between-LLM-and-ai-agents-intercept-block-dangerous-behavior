//go:build windows

package acpwrap

import (
	"os"
	"os/signal"
)

func forwardSignals() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	return ch
}

func stopSignals(ch chan os.Signal) {
	signal.Stop(ch)
	close(ch)
}
