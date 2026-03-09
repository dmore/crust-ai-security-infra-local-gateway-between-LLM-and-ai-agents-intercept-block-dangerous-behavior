package mcpgateway

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadSSEEvents_Basic(t *testing.T) {
	input := "event: message\ndata: hello\nid: 1\n\nevent: message\ndata: world\nid: 2\n\n"
	events := ReadSSEEvents(t.Context(), strings.NewReader(input))

	var got []SSEEvent
	for e := range events {
		got = append(got, e)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	if got[0].Type != "message" || got[0].Data != "hello" || got[0].ID != "1" {
		t.Errorf("event[0] = %+v", got[0])
	}
	if got[1].Type != "message" || got[1].Data != "world" || got[1].ID != "2" {
		t.Errorf("event[1] = %+v", got[1])
	}
}

func TestReadSSEEvents_MultiLineData(t *testing.T) {
	input := "data: line1\ndata: line2\ndata: line3\n\n"
	events := ReadSSEEvents(t.Context(), strings.NewReader(input))

	var got []SSEEvent
	for e := range events {
		got = append(got, e)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Data != "line1\nline2\nline3" {
		t.Errorf("data = %q, want %q", got[0].Data, "line1\nline2\nline3")
	}
}

func TestReadSSEEvents_CommentsIgnored(t *testing.T) {
	input := ": this is a comment\ndata: hello\n\n"
	events := ReadSSEEvents(t.Context(), strings.NewReader(input))

	var got []SSEEvent
	for e := range events {
		got = append(got, e)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Data != "hello" {
		t.Errorf("data = %q, want %q", got[0].Data, "hello")
	}
}

func TestReadSSEEvents_NoTrailingBlankLine(t *testing.T) {
	// Event without trailing blank line should still be flushed at EOF
	input := "data: orphan"
	events := ReadSSEEvents(t.Context(), strings.NewReader(input))

	var got []SSEEvent
	for e := range events {
		got = append(got, e)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Data != "orphan" {
		t.Errorf("data = %q, want %q", got[0].Data, "orphan")
	}
}

func TestReadSSEEvents_BlankLinesOnly(t *testing.T) {
	input := "\n\n\n"
	events := ReadSSEEvents(t.Context(), strings.NewReader(input))

	var got []SSEEvent
	for e := range events {
		got = append(got, e)
	}

	if len(got) != 0 {
		t.Errorf("expected 0 events from blank lines, got %d", len(got))
	}
}

func TestReadSSEEvents_DefaultEventType(t *testing.T) {
	input := "data: no type\n\n"
	events := ReadSSEEvents(t.Context(), strings.NewReader(input))

	var got []SSEEvent
	for e := range events {
		got = append(got, e)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	if got[0].Type != "" {
		t.Errorf("expected empty type, got %q", got[0].Type)
	}
	if got[0].Data != "no type" {
		t.Errorf("data = %q", got[0].Data)
	}
}

func TestWriteSSEEvent(t *testing.T) {
	tests := []struct {
		name   string
		event  SSEEvent
		expect string
	}{
		{
			"full event",
			SSEEvent{Type: "message", Data: "hello", ID: "42"},
			"event: message\nid: 42\ndata: hello\n\n",
		},
		{
			"data only",
			SSEEvent{Data: "hello"},
			"data: hello\n\n",
		},
		{
			"multi-line data",
			SSEEvent{Data: "line1\nline2"},
			"data: line1\ndata: line2\n\n",
		},
		{
			"event type only",
			SSEEvent{Type: "ping", Data: ""},
			"event: ping\ndata: \n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if err := WriteSSEEvent(w, tt.event); err != nil {
				t.Fatalf("WriteSSEEvent error: %v", err)
			}
			if got := w.Body.String(); got != tt.expect {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.expect)
			}
		})
	}
}

func TestProxySSEStream_InspectFilter(t *testing.T) {
	input := "event: message\ndata: allow\n\nevent: message\ndata: block\n\nevent: message\ndata: allow2\n\n"
	w := httptest.NewRecorder()

	inspect := func(e SSEEvent) (SSEEvent, bool) {
		if e.Data == "block" {
			return e, false
		}
		return e, true
	}

	ProxySSEStream(t.Context(), strings.NewReader(input), w, inspect)

	body := w.Body.String()
	if strings.Contains(body, "block") {
		t.Errorf("blocked event should not appear in output: %s", body)
	}
	if !strings.Contains(body, "allow") || !strings.Contains(body, "allow2") {
		t.Errorf("allowed events missing from output: %s", body)
	}
}

func TestReadSSEEvents_ReaderError(t *testing.T) {
	// A reader that returns an error after some data — scanner.Err() should catch it.
	// The channel should still close and deliver events read before the error.
	input := "data: before-error\n\n"
	r := &failAfterReader{data: []byte(input), failAfter: len(input)}
	events := ReadSSEEvents(t.Context(), r)

	var got []SSEEvent
	for e := range events {
		got = append(got, e)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 event before error, got %d", len(got))
	}
	if got[0].Data != "before-error" {
		t.Errorf("data = %q, want %q", got[0].Data, "before-error")
	}
}

// failAfterReader returns data normally, then returns an error on subsequent reads.
type failAfterReader struct {
	data      []byte
	pos       int
	failAfter int
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.pos >= r.failAfter {
		return 0, fmt.Errorf("simulated read error")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= r.failAfter {
		return n, nil // next call will error
	}
	return n, nil
}

func TestProxySSEStream_ContextCancel(t *testing.T) {
	// Large input to ensure the goroutine is still reading when we cancel
	var sb strings.Builder
	for range 100 {
		sb.WriteString("data: test\n\n")
	}

	ctx, cancel := context.WithCancel(t.Context())
	w := httptest.NewRecorder()

	count := 0
	inspect := func(e SSEEvent) (SSEEvent, bool) {
		count++
		if count >= 3 {
			cancel()
		}
		return e, true
	}

	ProxySSEStream(ctx, strings.NewReader(sb.String()), w, inspect)
	// Should exit without processing all 100 events
	if count >= 100 {
		t.Errorf("expected early exit on cancel, processed %d events", count)
	}
}
