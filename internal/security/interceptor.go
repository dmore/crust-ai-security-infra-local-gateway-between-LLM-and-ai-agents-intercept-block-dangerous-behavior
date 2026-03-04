package security

import (
	"encoding/json"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/message"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// API-specific protocol constants for content block types.
const (
	contentTypeToolUse      = "tool_use"      // Anthropic
	contentTypeFunctionCall = "function_call" // OpenAI Responses
)

// Interceptor handles tool call interception and response modification
type Interceptor struct {
	engine  *rules.Engine
	storage *telemetry.Storage
	enabled atomic.Bool
}

// NewInterceptor creates a new interceptor
func NewInterceptor(engine *rules.Engine, storage *telemetry.Storage) *Interceptor {
	i := &Interceptor{
		engine:  engine,
		storage: storage,
	}
	i.enabled.Store(true)
	return i
}

// SetEnabled enables or disables the interceptor
func (i *Interceptor) SetEnabled(enabled bool) {
	i.enabled.Store(enabled)
}

// IsEnabled returns whether the interceptor is enabled
func (i *Interceptor) IsEnabled() bool {
	return i.enabled.Load()
}

// GetEngine returns the rule engine
func (i *Interceptor) GetEngine() *rules.Engine {
	return i.engine
}

// GetStorage returns the storage
func (i *Interceptor) GetStorage() *telemetry.Storage {
	return i.storage
}

// InterceptionResult contains the result of intercepting tool calls
type InterceptionResult struct {
	ModifiedResponse []byte
	BlockedToolCalls []BlockedToolCall
	AllowedToolCalls []telemetry.ToolCall
	HasBlockedCalls  bool
}

// BlockedToolCall represents a tool call that was blocked
type BlockedToolCall struct {
	ToolCall    telemetry.ToolCall
	MatchResult rules.MatchResult
}

// intercept is the shared implementation for all three Intercept* format methods.
// It handles the guard check, result initialization, and final marshal.
// fn receives the result and useReplaceMode, applies format-specific filtering,
// and returns the (possibly modified) response value and whether it changed.
// Returning (nil, false) — e.g. on JSON parse failure — passes the original body through.
// Returning (nil, true) is treated the same way (silent passthrough); fn must not
// return modified=true with a nil response.
func (i *Interceptor) intercept(
	responseBody []byte,
	blockMode types.BlockMode,
	fn func(result *InterceptionResult, useReplaceMode bool) (any, bool),
) (*InterceptionResult, error) {
	if !i.enabled.Load() || i.engine == nil {
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}
	result := &InterceptionResult{
		BlockedToolCalls: make([]BlockedToolCall, 0),
		AllowedToolCalls: make([]telemetry.ToolCall, 0),
	}
	resp, modified := fn(result, blockMode.IsReplace())
	if !modified || resp == nil {
		result.ModifiedResponse = responseBody
		return result, nil
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return &InterceptionResult{ModifiedResponse: responseBody}, err
	}
	result.ModifiedResponse = b
	return result, nil
}

// InterceptOpenAIResponse intercepts tool calls in an OpenAI format response.
func (i *Interceptor) InterceptOpenAIResponse(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	return i.intercept(responseBody, blockMode, func(result *InterceptionResult, useReplaceMode bool) (any, bool) {
		var resp openAIResponse
		if err := json.Unmarshal(responseBody, &resp); err != nil {
			log.Warn("[Layer1] Failed to parse %s response: %v", apiType, err)
			return nil, false
		}
		modified := false
		for choiceIdx := range resp.Choices {
			choice := &resp.Choices[choiceIdx]
			if choice.Message.ToolCalls == nil {
				continue
			}
			allowed := make([]openAIToolCall, 0, len(choice.Message.ToolCalls))
			for _, tc := range choice.Message.ToolCalls {
				toolCall := telemetry.ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: json.RawMessage(tc.Function.Arguments)}
				_, blocked := i.evaluateToolCall(result, toolCall, traceID, sessionID, tc.Function.Arguments, apiType, model, useReplaceMode)
				if blocked {
					modified = true
				} else {
					allowed = append(allowed, tc)
				}
			}
			choice.Message.ToolCalls = allowed
		}
		if result.HasBlockedCalls && len(resp.Choices) > 0 {
			var msg string
			if useReplaceMode {
				msg = message.FormatReplaceWarning(toBlockedCalls(result.BlockedToolCalls))
			} else {
				msg = message.FormatRemoveWarning(toBlockedCalls(result.BlockedToolCalls))
			}
			if resp.Choices[0].Message.Content == "" {
				resp.Choices[0].Message.Content = msg
			} else {
				resp.Choices[0].Message.Content += "\n\n" + msg
			}
			modified = true
		}
		return resp, modified
	})
}

// InterceptAnthropicResponse intercepts tool calls in an Anthropic format response.
func (i *Interceptor) InterceptAnthropicResponse(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	return i.intercept(responseBody, blockMode, func(result *InterceptionResult, useReplaceMode bool) (any, bool) {
		var resp anthropicResponse
		if err := json.Unmarshal(responseBody, &resp); err != nil {
			log.Warn("[Layer1] Failed to parse %s response: %v", apiType, err)
			return nil, false
		}
		allowed := make([]anthropicContentBlock, 0, len(resp.Content))
		modified := false
		for _, block := range resp.Content {
			if block.Type != contentTypeToolUse {
				allowed = append(allowed, block)
				continue
			}
			tc := telemetry.ToolCall{ID: block.ID, Name: block.Name, Arguments: block.Input}
			matchResult, blocked := i.evaluateToolCall(result, tc, traceID, sessionID, string(block.Input), apiType, model, useReplaceMode)
			if blocked {
				modified = true
				if useReplaceMode {
					allowed = append(allowed, anthropicContentBlock{Type: "text", Text: message.FormatReplaceInline(block.Name, matchResult)})
				}
			} else {
				allowed = append(allowed, block)
			}
		}
		if result.HasBlockedCalls && !useReplaceMode {
			allowed = append(allowed, anthropicContentBlock{Type: "text", Text: message.FormatRemoveWarning(toBlockedCalls(result.BlockedToolCalls))})
			modified = true
		}
		resp.Content = allowed
		return resp, modified
	})
}

// InterceptOpenAIResponsesResponse intercepts tool calls in an OpenAI Responses API format response.
// The Responses API uses `output[]` with `type: "function_call"` items.
func (i *Interceptor) InterceptOpenAIResponsesResponse(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	return i.intercept(responseBody, blockMode, func(result *InterceptionResult, useReplaceMode bool) (any, bool) {
		var resp openAIResponsesResponse
		if err := json.Unmarshal(responseBody, &resp); err != nil {
			log.Warn("[Layer1] Failed to parse %s response: %v", apiType, err)
			return nil, false
		}
		allowed := make([]openAIResponsesOutputItem, 0, len(resp.Output))
		modified := false
		for _, item := range resp.Output {
			if item.Type != contentTypeFunctionCall {
				allowed = append(allowed, item)
				continue
			}
			tc := telemetry.ToolCall{ID: item.CallID, Name: item.Name, Arguments: json.RawMessage(item.Arguments)}
			matchResult, blocked := i.evaluateToolCall(result, tc, traceID, sessionID, item.Arguments, apiType, model, useReplaceMode)
			if blocked {
				modified = true
				if useReplaceMode {
					allowed = append(allowed, openAIResponsesOutputItem{
						Type: "message", ID: item.ID,
						Content: []openAIResponsesContent{{Type: "output_text", Text: message.FormatReplaceInline(item.Name, matchResult)}},
					})
				}
			} else {
				allowed = append(allowed, item)
			}
		}
		if result.HasBlockedCalls && !useReplaceMode {
			allowed = append(allowed, openAIResponsesOutputItem{
				Type:    "message",
				Content: []openAIResponsesContent{{Type: "output_text", Text: message.FormatRemoveWarning(toBlockedCalls(result.BlockedToolCalls))}},
			})
			modified = true
		}
		resp.Output = allowed
		return resp, modified
	})
}

// InterceptToolCalls intercepts tool calls based on API type
// blockMode: types.BlockModeRemove (delete tool calls) or types.BlockModeReplace (substitute with a text warning block)
func (i *Interceptor) InterceptToolCalls(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	switch apiType {
	case types.APITypeAnthropic:
		return i.InterceptAnthropicResponse(responseBody, traceID, sessionID, model, apiType, blockMode)
	case types.APITypeOpenAIResponses:
		return i.InterceptOpenAIResponsesResponse(responseBody, traceID, sessionID, model, apiType, blockMode)
	case types.APITypeOpenAICompletion, types.APITypeUnknown:
		return i.InterceptOpenAIResponse(responseBody, traceID, sessionID, model, apiType, blockMode)
	default:
		panic("unhandled types.APIType: " + apiType.String())
	}
}

// evaluateToolCall evaluates a single tool call against the rules engine.
// Returns the match result. Handles logging, metrics, and result bookkeeping.
// Returns true if the tool call was blocked.
func (i *Interceptor) evaluateToolCall(
	result *InterceptionResult,
	tc telemetry.ToolCall,
	traceID, sessionID, argsString string,
	apiType types.APIType,
	model string,
	useReplaceMode bool,
) (rules.MatchResult, bool) {
	matchResult := i.engine.Evaluate(rules.ToolCall{
		Name:      tc.Name,
		Arguments: tc.Arguments,
	})

	isBlocked := matchResult.Matched && matchResult.Action == rules.ActionBlock
	ruleName := ""
	if matchResult.Matched {
		ruleName = matchResult.RuleName
	}

	RecordEvent(Event{
		Layer:      LayerL1,
		TraceID:    traceID,
		SessionID:  sessionID,
		ToolName:   tc.Name,
		Arguments:  json.RawMessage(argsString),
		APIType:    apiType,
		Model:      model,
		WasBlocked: isBlocked,
		RuleName:   ruleName,
	})

	if isBlocked {
		result.BlockedToolCalls = append(result.BlockedToolCalls, BlockedToolCall{
			ToolCall:    tc,
			MatchResult: matchResult,
		})
		result.HasBlockedCalls = true
		if useReplaceMode {
			log.Warn("[Layer1] Replaced: %s (rule: %s)", tc.Name, matchResult.RuleName)
		} else {
			log.Warn("[Layer1] Blocked: %s (rule: %s)", tc.Name, matchResult.RuleName)
		}
		return matchResult, true
	}

	result.AllowedToolCalls = append(result.AllowedToolCalls, tc)
	return matchResult, false
}

// BuildWarningContent builds a warning message listing blocked tool calls.
// Delegates to message.FormatRemoveWarning for centralized formatting.
func BuildWarningContent(blockedCalls []BlockedToolCall) string {
	return message.FormatRemoveWarning(toBlockedCalls(blockedCalls))
}

// toBlockedCalls converts []BlockedToolCall to []message.BlockedCall.
func toBlockedCalls(blockedCalls []BlockedToolCall) []message.BlockedCall {
	out := make([]message.BlockedCall, len(blockedCalls))
	for i, bc := range blockedCalls {
		out[i] = message.BlockedCall{
			ToolName:    bc.ToolCall.Name,
			MatchResult: bc.MatchResult,
		}
	}
	return out
}

// OpenAI response structures
type openAIResponse struct {
	ID      string         `json:"id,omitempty"`
	Object  string         `json:"object,omitempty"`
	Created int64          `json:"created,omitempty"`
	Model   string         `json:"model,omitempty"`
	Choices []openAIChoice `json:"choices,omitempty"`
	Usage   *openAIUsage   `json:"usage,omitempty"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIChoice struct {
	Index        int            `json:"index"`
	Message      openAIMessage  `json:"message,omitzero"`
	Delta        *openAIMessage `json:"delta,omitempty"`
	FinishReason string         `json:"finish_reason,omitempty"`
}

type openAIMessage struct {
	Role      string           `json:"role,omitempty"`
	Content   string           `json:"content,omitempty"`
	ToolCalls []openAIToolCall `json:"tool_calls,omitempty"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Anthropic response structures
type anthropicResponse struct {
	ID           string                  `json:"id,omitempty"`
	Type         string                  `json:"type,omitempty"`
	Role         string                  `json:"role,omitempty"`
	Content      []anthropicContentBlock `json:"content,omitempty"`
	Model        string                  `json:"model,omitempty"`
	StopReason   string                  `json:"stop_reason,omitempty"`
	StopSequence string                  `json:"stop_sequence,omitempty"`
	Usage        *anthropicUsage         `json:"usage,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicContentBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	Text  string          `json:"text,omitempty"`
}

// OpenAI Responses API structures
type openAIResponsesResponse struct {
	ID     string                      `json:"id,omitempty"`
	Object string                      `json:"object,omitempty"`
	Model  string                      `json:"model,omitempty"`
	Output []openAIResponsesOutputItem `json:"output,omitempty"`
	Usage  *openAIResponsesUsage       `json:"usage,omitempty"`
}

type openAIResponsesOutputItem struct {
	Type      string                   `json:"type"`
	ID        string                   `json:"id,omitempty"`
	CallID    string                   `json:"call_id,omitempty"`
	Name      string                   `json:"name,omitempty"`
	Arguments string                   `json:"arguments,omitempty"`
	Content   []openAIResponsesContent `json:"content,omitempty"`
}

type openAIResponsesContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type openAIResponsesUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}
