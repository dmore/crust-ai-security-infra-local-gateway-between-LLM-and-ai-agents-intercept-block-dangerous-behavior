//go:build !windows

package acpwrap

import (
	"os"
	"os/signal"
	"syscall"
)

func forwardSignals() chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	return ch
}

func stopSignals(ch chan os.Signal) {
	signal.Stop(ch)
	close(ch)
}
