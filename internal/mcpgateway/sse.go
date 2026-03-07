package mcpgateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SSEEvent represents a single Server-Sent Event.
type SSEEvent struct {
	Type string // event type ("message", "endpoint", etc.); empty for default
	Data string // data field content (may be multi-line, joined by newlines)
	ID   string // optional event ID for reconnection
}

// ReadSSEEvents reads SSE events from r and sends them on the returned channel.
// The channel is closed when r returns EOF or ctx is canceled.
func ReadSSEEvents(ctx context.Context, r io.Reader) <-chan SSEEvent {
	ch := make(chan SSEEvent, 8)
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // up to 1MB per SSE line
		var event SSEEvent
		var dataLines []string

		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Text()

			// Blank line = dispatch event
			if line == "" {
				if len(dataLines) > 0 {
					event.Data = strings.Join(dataLines, "\n")
					select {
					case ch <- event:
					case <-ctx.Done():
						return
					}
				}
				event = SSEEvent{}
				dataLines = nil
				continue
			}

			// Comment lines (start with ':') are ignored
			if strings.HasPrefix(line, ":") {
				continue
			}

			// Parse "field: value" or "field:value"
			field, value, _ := strings.Cut(line, ":")
			// Per SSE spec: if value starts with a space, strip it
			value = strings.TrimPrefix(value, " ")

			switch field {
			case "event":
				event.Type = value
			case "data":
				dataLines = append(dataLines, value)
			case "id":
				event.ID = value
			}
		}

		if err := scanner.Err(); err != nil {
			log.Warn("SSE scanner error: %v", err)
		}

		// Flush any pending event at EOF (no trailing blank line)
		if len(dataLines) > 0 {
			event.Data = strings.Join(dataLines, "\n")
			select {
			case ch <- event:
			case <-ctx.Done():
			}
		}
	}()
	return ch
}

// WriteSSEEvent writes an SSE event to an http.ResponseWriter and flushes.
func WriteSSEEvent(w http.ResponseWriter, event SSEEvent) error {
	if event.Type != "" {
		if _, err := fmt.Fprintf(w, "event: %s\n", event.Type); err != nil {
			return err
		}
	}
	if event.ID != "" {
		if _, err := fmt.Fprintf(w, "id: %s\n", event.ID); err != nil {
			return err
		}
	}
	// Write data lines (each line gets its own "data:" prefix)
	for line := range strings.SplitSeq(event.Data, "\n") {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	// Trailing blank line to dispatch the event
	if _, err := fmt.Fprint(w, "\n"); err != nil {
		return err
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

// ProxySSEStream reads SSE events from r, passes each through the inspect function,
// and writes allowed events to w. The inspect function returns the (possibly modified)
// event and a bool indicating whether to forward it (true) or drop it (false).
func ProxySSEStream(ctx context.Context, r io.Reader, w http.ResponseWriter,
	inspect func(SSEEvent) (SSEEvent, bool)) {

	events := ReadSSEEvents(ctx, r)
	for event := range events {
		select {
		case <-ctx.Done():
			return
		default:
		}

		out, ok := inspect(event)
		if !ok {
			continue // drop blocked event
		}
		if err := WriteSSEEvent(w, out); err != nil {
			return
		}
	}
}
