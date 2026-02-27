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

		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			if err := fwdWriter.WriteLine(line); err != nil {
				log.Debug("%s write error: %v", label, err)
				return
			}
			continue
		}

		if !msg.IsRequest() {
			// Response DLP: scan responses for leaked secrets.
			// Errors go to fwdWriter (client) because the client is waiting
			// for this response — the server doesn't need to know.
			if len(msg.Result) > 0 {
				if dlpResult := engine.ScanDLP(string(msg.Result)); dlpResult != nil {
					log.Warn("Blocked %s response (DLP): rule=%s message=%s",
						protocol, dlpResult.RuleName, dlpResult.Message)
					SendBlockError(log, fwdWriter, msg.ID,
						fmt.Sprintf("[Crust] Blocked by rule %q: %s", dlpResult.RuleName, dlpResult.Message))
					continue
				}
			}
			if len(msg.Error) > 0 {
				if dlpResult := engine.ScanDLP(string(msg.Error)); dlpResult != nil {
					log.Warn("Blocked %s error response (DLP): rule=%s message=%s",
						protocol, dlpResult.RuleName, dlpResult.Message)
					SendBlockError(log, fwdWriter, msg.ID,
						fmt.Sprintf("[Crust] Blocked by rule %q: %s", dlpResult.RuleName, dlpResult.Message))
					continue
				}
			}
			if err := fwdWriter.WriteLine(line); err != nil {
				log.Debug("%s write error: %v", label, err)
				return
			}
			continue
		}

		toolCall, err := convert(msg.Method, msg.Params)
		if toolCall == nil && err == nil {
			if err := fwdWriter.WriteLine(line); err != nil {
				log.Debug("%s write error: %v", label, err)
				return
			}
			continue
		}
		if err != nil {
			log.Warn("Blocked %s %s: %v", protocol, msg.Method, err)
			SendBlockError(log, errWriter, msg.ID, "[Crust] Blocked: malformed params for "+msg.Method)
			continue
		}

		result := engine.Evaluate(*toolCall)

		if result.Matched && result.Action == rules.ActionBlock {
			log.Warn("Blocked %s %s (tool=%s): rule=%s message=%s",
				protocol, msg.Method, toolCall.Name, result.RuleName, result.Message)
			SendBlockError(log, errWriter, msg.ID,
				fmt.Sprintf("[Crust] Blocked by rule %q: %s", result.RuleName, result.Message))
			continue
		}

		if result.Matched && result.Action == rules.ActionLog {
			log.Info("Logged %s %s (tool=%s): rule=%s",
				protocol, msg.Method, toolCall.Name, result.RuleName)
		}

		if err := fwdWriter.WriteLine(line); err != nil {
			log.Debug("%s write error: %v", label, err)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Warn("%s scanner error: %v", label, err)
	}
}
