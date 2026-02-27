package jsonrpc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

// SendBlockError sends a JSON-RPC error response back through the writer.
func SendBlockError(log *logger.Logger, writer *LockedWriter, id json.RawMessage, msg string) {
	resp, err := json.Marshal(ErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   ErrorObj{Code: BlockedError, Message: msg},
	})
	if err != nil {
		log.Debug("Failed to marshal block response: %v", err)
		return
	}
	if err := writer.WriteLine(resp); err != nil {
		log.Debug("Failed to send block response: %v", err)
	}
}

// PipePassthrough reads JSONL from src and forwards each line to dst.
func PipePassthrough(log *logger.Logger, src io.Reader, dst *LockedWriter, label string) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxScannerBuf)

	for scanner.Scan() {
		if err := dst.WriteLine(scanner.Bytes()); err != nil {
			log.Debug("%s write error: %v", label, err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		log.Warn("%s scanner error: %v", label, err)
	}
}

// processResult indicates what happened when processing a single message.
type processResult int

const (
	resultForwarded processResult = iota // message was forwarded
	resultBlocked                        // message was blocked
	resultWriteErr                       // write error; caller should abort
)

// processMessage inspects a single JSON-RPC message and either forwards or blocks it.
// This is the core inspection logic, reused by both the main loop and batch handler.
func processMessage(log *logger.Logger, engine *rules.Engine, line []byte, msg *Message,
	fwdWriter, errWriter *LockedWriter, convert MethodConverter, protocol, label string) processResult {

	if !msg.IsRequest() {
		// Response DLP: scan Result, Error, and notification Params for leaked secrets.
		// Errors go to fwdWriter (client) because the client is waiting for this response.
		if len(msg.Result) > 0 {
			if dlpResult := engine.ScanDLP(string(msg.Result)); dlpResult != nil {
				log.Warn("Blocked %s response (DLP): rule=%s message=%s",
					protocol, dlpResult.RuleName, dlpResult.Message)
				SendBlockError(log, fwdWriter, msg.ID,
					fmt.Sprintf("[Crust] Blocked by rule %q: %s", dlpResult.RuleName, dlpResult.Message))
				return resultBlocked
			}
		}
		if len(msg.Error) > 0 {
			if dlpResult := engine.ScanDLP(string(msg.Error)); dlpResult != nil {
				log.Warn("Blocked %s error response (DLP): rule=%s message=%s",
					protocol, dlpResult.RuleName, dlpResult.Message)
				SendBlockError(log, fwdWriter, msg.ID,
					fmt.Sprintf("[Crust] Blocked by rule %q: %s", dlpResult.RuleName, dlpResult.Message))
				return resultBlocked
			}
		}
		// Notification params DLP: notifications have Method+Params but no ID.
		// A malicious server could embed secrets in notification params.
		if msg.IsNotification() && len(msg.Params) > 0 {
			if dlpResult := engine.ScanDLP(string(msg.Params)); dlpResult != nil {
				log.Warn("Blocked %s notification (DLP): method=%s rule=%s message=%s",
					protocol, msg.Method, dlpResult.RuleName, dlpResult.Message)
				// Notifications have no ID — can't send an error response.
				// Drop silently (don't forward).
				return resultBlocked
			}
		}
		if err := fwdWriter.WriteLine(line); err != nil {
			log.Debug("%s write error: %v", label, err)
			return resultWriteErr
		}
		return resultForwarded
	}

	// Request: convert method and evaluate rules.
	toolCall, err := convert(msg.Method, msg.Params)
	if toolCall == nil && err == nil {
		if err := fwdWriter.WriteLine(line); err != nil {
			log.Debug("%s write error: %v", label, err)
			return resultWriteErr
		}
		return resultForwarded
	}
	if err != nil {
		log.Warn("Blocked %s %s: %v", protocol, msg.Method, err)
		SendBlockError(log, errWriter, msg.ID, "[Crust] Blocked: malformed params for "+msg.Method)
		return resultBlocked
	}

	result := engine.Evaluate(*toolCall)

	if result.Matched && result.Action == rules.ActionBlock {
		log.Warn("Blocked %s %s (tool=%s): rule=%s message=%s",
			protocol, msg.Method, toolCall.Name, result.RuleName, result.Message)
		SendBlockError(log, errWriter, msg.ID,
			fmt.Sprintf("[Crust] Blocked by rule %q: %s", result.RuleName, result.Message))
		return resultBlocked
	}

	if result.Matched && result.Action == rules.ActionLog {
		log.Info("Logged %s %s (tool=%s): rule=%s",
			protocol, msg.Method, toolCall.Name, result.RuleName)
	}

	if err := fwdWriter.WriteLine(line); err != nil {
		log.Debug("%s write error: %v", label, err)
		return resultWriteErr
	}
	return resultForwarded
}

// processBatch handles a JSON-RPC batch array by inspecting each element
// individually. Each allowed element is forwarded as an individual JSONL line.
// MCP stdio transport is JSONL, so splitting batches is correct behavior.
func processBatch(log *logger.Logger, engine *rules.Engine, line []byte,
	fwdWriter, errWriter *LockedWriter, convert MethodConverter, protocol, label string) processResult {

	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		// Not a valid JSON array — forward as-is (same as invalid JSON)
		log.Debug("%s batch parse error: %v", label, err)
		if err := fwdWriter.WriteLine(line); err != nil {
			log.Debug("%s write error: %v", label, err)
			return resultWriteErr
		}
		return resultForwarded
	}

	if len(batch) == 0 {
		if err := fwdWriter.WriteLine(line); err != nil {
			log.Debug("%s write error: %v", label, err)
			return resultWriteErr
		}
		return resultForwarded
	}

	log.Debug("%s processing batch of %d messages", label, len(batch))

	for _, raw := range batch {
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			// Element is not valid JSON-RPC — forward individually
			if err := fwdWriter.WriteLine(raw); err != nil {
				log.Debug("%s write error: %v", label, err)
				return resultWriteErr
			}
			continue
		}

		if processMessage(log, engine, raw, &msg, fwdWriter, errWriter, convert, protocol, label) == resultWriteErr {
			return resultWriteErr
		}
	}

	return resultForwarded
}

// PipeInspect reads JSONL from src, runs security-relevant messages through
// the converter and rule engine, and either forwards or blocks them.
//
// Parameters:
//   - fwdWriter: where allowed messages are forwarded
//   - errWriter: where JSON-RPC error responses for blocked messages are sent
//   - convert: the protocol-specific method converter
//   - protocol: "ACP" or "MCP" (for log messages)
//   - label: direction label for debug logs (e.g., "Agent->IDE")
func PipeInspect(log *logger.Logger, engine *rules.Engine, src io.Reader,
	fwdWriter, errWriter *LockedWriter, convert MethodConverter, protocol, label string) {

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxScannerBuf)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			if err := fwdWriter.WriteLine(line); err != nil {
				log.Debug("%s write error: %v", label, err)
				return
			}
			continue
		}

		// Detect JSON-RPC batch arrays. Per JSON-RPC 2.0 spec, batch requests
		// are JSON arrays. Without this check, arrays fail to unmarshal into
		// the Message struct and are forwarded unexamined (security bypass).
		if line[0] == '[' {
			if processBatch(log, engine, line, fwdWriter, errWriter, convert, protocol, label) == resultWriteErr {
				return
			}
			continue
		}

		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			if err := fwdWriter.WriteLine(line); err != nil {
				log.Debug("%s write error: %v", label, err)
				return
			}
			continue
		}

		if processMessage(log, engine, line, &msg, fwdWriter, errWriter, convert, protocol, label) == resultWriteErr {
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Warn("%s scanner error: %v", label, err)
	}
}
