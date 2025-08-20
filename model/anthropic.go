// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	anthropic "github.com/anthropics/anthropic-sdk-go"
	anthropic_bedrock "github.com/anthropics/anthropic-sdk-go/bedrock"
	anthropic_option "github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
	anthropic_vertex "github.com/anthropics/anthropic-sdk-go/vertex"
	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/internal/pool"
	"github.com/go-a2a/adk-go/types"
)

// ClaudeMode represents a mode of the Claude model.
type ClaudeMode int

const (
	// ClaudeModeAnthropic is the mode for Anthropic's official models.
	ClaudeModeAnthropic ClaudeMode = iota

	// ClaudeModeVertexAI is the mode for Google Cloud Platform (GCP) Vertex AI models.
	ClaudeModeVertexAI

	// ClaudeModeBedrock is the mode for Amazon Web Services (AWS) Bedrock models.
	ClaudeModeBedrock
)

// detectClaudeDefaultModel returns the default model name based on the mode.
func detectClaudeDefaultModel(mode ClaudeMode) string {
	switch mode {
	case ClaudeModeAnthropic:
		return string(anthropic.ModelClaude3_5Sonnet20241022)
	case ClaudeModeVertexAI:
		return "claude-3-5-sonnet-v2@20241022"
	case ClaudeModeBedrock:
		return "anthropic.claude-3-5-sonnet-20241022-v2:0"
	default:
		return ""
	}
}

var genAIRoles = []Role{
	RoleModel,
	RoleAssistant,
}

// toClaudeRole converts [genai.Role] to [anthropic.MessageParamRole].
func (m *Claude) toClaudeRole(role string) anthropic.MessageParamRole {
	if slices.Contains(genAIRoles, role) {
		return anthropic.MessageParamRoleAssistant
	}
	return anthropic.MessageParamRoleUser
}

var claudeStopReasons = []anthropic.StopReason{
	anthropic.StopReasonEndTurn,
	anthropic.StopReasonStopSequence,
	anthropic.StopReasonToolUse,
}

// toGenAIFinishReason converts [anthropic.StopReason] to [genai.FinishReason].
func (m *Claude) toGenAIFinishReason(stopReason anthropic.StopReason) genai.FinishReason {
	if slices.Contains(claudeStopReasons, stopReason) {
		return genai.FinishReasonStop
	}

	if stopReason == anthropic.StopReasonMaxTokens {
		return genai.FinishReasonMaxTokens
	}

	return genai.FinishReasonUnspecified
}

func (m *Claude) isImagePart(part *genai.Part) bool {
	return part.InlineData != nil && strings.HasPrefix(part.InlineData.MIMEType, "image")
}

// partToMessageBlock converts [*genai.Part] to [anthropic.ContentBlockParamUnion].
func (m *Claude) partToMessageBlock(part *genai.Part) (anthropic.ContentBlockParamUnion, error) {
	switch {
	case part.Text != "":
		params := anthropic.NewTextBlock(part.Text)
		return params, nil

	case part.FunctionCall != nil:
		funcCall := part.FunctionCall
		// Assert function call name if [genai.Part.FunctionCall] is non-nil
		if funcCall.Name != "" {
			return anthropic.ContentBlockParamUnion{}, errors.New("FunctionCall name is empty")
		}
		params := anthropic.NewToolUseBlock(funcCall.ID, funcCall.Args, funcCall.Name)
		return params, nil

	case part.FunctionResponse != nil:
		funcResp := part.FunctionResponse
		if content, ok := funcResp.Response["result"]; ok {
			params := anthropic.NewToolResultBlock(funcResp.ID, content.(string), false)
			return params, nil
		}

	case m.isImagePart(part):
		data := base64.StdEncoding.EncodeToString(part.InlineData.Data)
		param := anthropic.Base64ImageSourceParam{
			Data:      data,
			MediaType: anthropic.Base64ImageSourceMediaType(part.InlineData.MIMEType),
		}
		return anthropic.NewImageBlock(param), nil

	case part.ExecutableCode != nil:
		return anthropic.NewTextBlock("Code:```" + string(part.ExecutableCode.Language) + "\n" + part.ExecutableCode.Code + "\n```"), nil

	case part.CodeExecutionResult != nil:
		return anthropic.NewTextBlock("Execution Result:```code_output\n" + part.CodeExecutionResult.Output + "\n```"), nil
	}

	return anthropic.ContentBlockParamUnion{}, fmt.Errorf("not supported yet %T part type", part)
}

// contentToMessageParam converts [*genai.Content] to [anthropic.MessageParam].
func (m *Claude) contentToMessageParam(ctx context.Context, content *genai.Content) anthropic.MessageParam {
	// Skip system messages (handled separately in Generate/StreamGenerate)
	if content.Role == RoleSystem {
		return anthropic.MessageParam{}
	}

	msgParam := anthropic.MessageParam{
		Role:    m.toClaudeRole(content.Role),
		Content: make([]anthropic.ContentBlockParamUnion, 0, len(content.Parts)),
	}
	for _, part := range content.Parts {
		if m.isImagePart(part) {
			m.logger.WarnContext(ctx, "Image data is not supported in Claude for model turns")
			continue
		}

		msgBlock, err := m.partToMessageBlock(part)
		if err != nil {
			continue
		}
		msgParam.Content = append(msgParam.Content, msgBlock)
	}

	return msgParam
}

// contentBlockToPart converts [anthropic.ContentBlockUnion] to [*genai.Part].
func (m *Claude) contentBlockToPart(contentBlock anthropic.ContentBlockUnion) (*genai.Part, error) {
	switch cBlock := contentBlock.AsAny().(type) {
	case anthropic.TextBlock:
		return genai.NewPartFromText(cBlock.Text), nil

	case anthropic.ToolUseBlock:
		if cBlock.Input == nil {
			return nil, fmt.Errorf("input field must be non-nil: %#v", cBlock)
		}
		var args map[string]any
		if err := json.UnmarshalRead(bytes.NewReader(cBlock.Input), args, json.DefaultOptionsV2()); err != nil {
			return nil, fmt.Errorf("unmarshal ToolUseBlock input: %w", err)
		}
		part := genai.NewPartFromFunctionCall(cBlock.Name, args)
		part.FunctionCall.ID = cBlock.ID
		return part, nil

	case anthropic.ThinkingBlock, anthropic.RedactedThinkingBlock:
		return nil, fmt.Errorf("not supported yet converts %T content block", cBlock)
	}

	return nil, fmt.Errorf("unreachable: no variant present")
}

// messageToGenerateContentResponse converts [*anthropic.Message] to [*LLMResponse].
func (m *Claude) messageToGenerateContentResponse(ctx context.Context, message *anthropic.Message) *types.LLMResponse {
	sb := pool.String.Get() // for log output
	enc := jsontext.NewEncoder(sb, jsontext.WithIndentPrefix("\t"), jsontext.WithIndent("  "))
	if err := json.MarshalEncode(enc, message); err == nil {
		m.logger.InfoContext(ctx, "Claude response", slog.String("response", sb.String()))
	}
	pool.String.Put(sb)

	parts := make([]*genai.Part, 0, len(message.Content))
	for _, content := range message.Content {
		part, err := m.contentBlockToPart(content)
		if err != nil {
			continue
		}
		parts = append(parts, part)
	}

	usageMetadata := &genai.GenerateContentResponseUsageMetadata{
		PromptTokenCount:     int32(message.Usage.InputTokens),
		CandidatesTokenCount: int32(message.Usage.OutputTokens),
		TotalTokenCount:      int32(message.Usage.InputTokens + message.Usage.OutputTokens),
	}

	return &types.LLMResponse{
		Content: &genai.Content{
			Role:  RoleModel,
			Parts: parts,
		},
		UsageMetadata: usageMetadata,
		FinishReason:  m.toGenAIFinishReason(message.StopReason),
	}
}

// funcDeclarationToToolParam converts [*genai.FunctionDeclaration] to [anthropic.ToolUnionParam].
func (m *Claude) funcDeclarationToToolParam(funcDeclaration *genai.FunctionDeclaration) (toolUnion anthropic.ToolUnionParam, err error) {
	if funcDeclaration.Name == "" {
		return toolUnion, errors.New("functionDeclaration name is empty")
	}

	properties := make(map[string]*genai.Schema)
	var requiredParams []string
	if params := funcDeclaration.Parameters; params != nil && params.Properties != nil {
		maps.Insert(properties, maps.All(params.Properties))
		if len(params.Required) > 0 {
			requiredParams = append(requiredParams, params.Required...)
		}
	}
	inputSchema := anthropic.ToolInputSchemaParam{
		Properties: properties,
		Required:   requiredParams,
	}

	toolUnion = anthropic.ToolUnionParamOfTool(inputSchema, funcDeclaration.Name)
	toolUnion.OfTool.Description = param.NewOpt(funcDeclaration.Description)

	return toolUnion, nil
}

// Claude represents an integration with Claude models served from Vertex AI.
type Claude struct {
	anthropicClient anthropic.Client
	// modelName represents the specific LLM model name.
	modelName string
	// logger is the logger used for logging.
	logger *slog.Logger

	// optional [*http.Client] to use.
	hc *http.Client
	// The maximum number of tokens to generate.
	maxTokens int64
}

var _ types.Model = (*Claude)(nil)

func WithMaxTokens(maxToken int64) Option[Claude] {
	return func(m *Claude) {
		m.maxTokens = maxToken
	}
}

// NewClaude creates a new Claude LLM instance.
func NewClaude(ctx context.Context, modelName string, mode ClaudeMode, opts ...Option[Claude]) (*Claude, error) {
	// Use default model if none provided
	if modelName == "" {
		modelName = detectClaudeDefaultModel(mode)
	}

	claude := &Claude{
		modelName: modelName,
		logger:    slog.Default(),
		hc:        &http.Client{},
		maxTokens: 8192,
	}
	for _, opt := range opts {
		opt(claude)
	}

	ropts := []anthropic_option.RequestOption{
		anthropic_option.WithHTTPClient(claude.hc),
	}
	switch mode {
	case ClaudeModeAnthropic:
		ropts = append(ropts, anthropic.DefaultClientOptions()...)

	case ClaudeModeVertexAI:
		projectID := os.Getenv(EnvGoogleCloudProject)
		if projectID == "" {
			return nil, fmt.Errorf("%q is required", EnvGoogleCloudProject)
		}
		location := cmp.Or(os.Getenv(EnvGoogleCloudLocation), os.Getenv(EnvGoogleCloudRegion))
		if location == "" {
			return nil, fmt.Errorf("%q or %q is required", EnvGoogleCloudLocation, EnvGoogleCloudRegion)
		}
		scopes := aiplatform.DefaultAuthScopes()
		ropts = append(ropts, anthropic_vertex.WithGoogleAuth(ctx, location, projectID, scopes...))

	case ClaudeModeBedrock:
		ropts = append(ropts, anthropic_bedrock.WithLoadDefaultConfig(ctx))
	}

	claude.anthropicClient = anthropic.NewClient(ropts...)

	return claude, nil
}

// Name returns the name of the [Claude] model.
//
// Name implements [types.Model].
func (m *Claude) Name() string {
	return m.modelName
}

// SupportedModels returns a list of supported models in the [Claude].
//
// See https://docs.anthropic.com/en/docs/about-claude/models/all-models.
//
// SupportedModels implements [types.Model].
func (m *Claude) SupportedModels() []string {
	return []string{
		// Anthropic API
		string(anthropic.ModelClaude3_7SonnetLatest),
		string(anthropic.ModelClaude3_7Sonnet20250219),
		string(anthropic.ModelClaude3_5HaikuLatest),
		string(anthropic.ModelClaude3_5Haiku20241022),
		string(anthropic.ModelClaudeSonnet4_20250514),
		string(anthropic.ModelClaudeSonnet4_0),
		string(anthropic.ModelClaude4Sonnet20250514),
		string(anthropic.ModelClaude3_5SonnetLatest),
		string(anthropic.ModelClaude3_5Sonnet20241022),
		string(anthropic.ModelClaude_3_5_Sonnet_20240620),
		string(anthropic.ModelClaudeOpus4_0),
		string(anthropic.ModelClaudeOpus4_20250514),
		string(anthropic.ModelClaude4Opus20250514),
		string(anthropic.ModelClaudeOpus4_1_20250805),

		// GCP Vertex AI
		"claude-3-7-sonnet@20250219",
		"claude-3-5-haiku@20241022",
		"claude-sonnet-4@20250514",
		"claude-3-5-sonnet-v2@20241022",
		"claude-opus-4@20250514",
		"claude-opus-4-1@20250805",

		// AWS Bedrock
		"anthropic.claude-3-7-sonnet-20250219-v1:0",
		"anthropic.claude-3-5-haiku-20241022-v1:0",
		"anthropic.claude-sonnet-4-20250514-v1:0",
		"anthropic.claude-3-5-sonnet-20241022-v2:0",
		"anthropic.claude-opus-4-20250514-v1:0",
		"anthropic.claude-opus-4-1-20250805-v1:0",
	}
}

// Connect creates a live connection to the Claude LLM.
//
// Connect implements [types.Model].
//
// TODO(zchee): implements.
func (m *Claude) Connect(context.Context, *types.LLMRequest) (types.ModelConnection, error) {
	// Ensure we can get an Anthropic client
	_ = m.anthropicClient

	// For now, this is a placeholder as we haven't implemented ClaudeConnection yet
	// In a real implementation, we would return a proper ClaudeConnection
	return nil, fmt.Errorf("ClaudeConnection not implemented yet")
}

// GenerateContent generates content from the model.
//
// GenerateContent implements [types.Model].
func (m *Claude) GenerateContent(ctx context.Context, request *types.LLMRequest) (*types.LLMResponse, error) {
	// Convert messages to Anthropic format
	messages := make([]anthropic.MessageParam, len(request.Contents))
	for i, content := range request.Contents {
		messages[i] = m.contentToMessageParam(ctx, content)
	}

	// Prepare parameters
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(m.modelName),
		Messages:  messages,
		MaxTokens: m.maxTokens,
	}

	// Apply generation config if provided
	if config := request.Config; config != nil {
		// MaxOutputTokens is an int32 directly, not a pointer
		if config.MaxOutputTokens > 0 {
			params.MaxTokens = int64(config.MaxOutputTokens)
		}

		if config.Temperature != nil {
			params.Temperature = anthropic.Float(float64(*config.Temperature))
		}

		if config.TopK != nil {
			params.TopK = anthropic.Int(int64(*config.TopK))
		}

		if config.TopP != nil {
			params.TopP = anthropic.Float(float64(*config.TopP))
		}

		if config.SystemInstruction != nil {
			for _, instruction := range config.SystemInstruction.Parts {
				params.System = append(params.System, anthropic.TextBlockParam{
					Text: instruction.Text,
				})
			}
		}

		// Add tools if provided
		if len(config.Tools) > 0 && config.Tools[0].FunctionDeclarations != nil {
			tools := make([]anthropic.ToolUnionParam, 0, len(config.Tools[0].FunctionDeclarations))
			for _, funcDeclarations := range config.Tools[0].FunctionDeclarations {
				toolUnion, err := m.funcDeclarationToToolParam(funcDeclarations)
				if err != nil {
					return nil, err
				}
				tools = append(tools, toolUnion)
			}
			params.Tools = tools
		}
	}

	if len(request.ToolMap) > 0 {
		toolchoice := anthropic.ToolChoiceUnionParam{
			OfAuto: &anthropic.ToolChoiceAutoParam{
				DisableParallelToolUse: anthropic.Bool(false),
			},
		}
		params.ToolChoice = toolchoice
	}

	// Make API call
	resp, err := m.anthropicClient.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("claude API error: %w", err)
	}

	return m.messageToGenerateContentResponse(ctx, resp), nil
}

// StreamGenerateContent streams generated content from the model.
//
// StreamGenerateContent implements [types.Model].
func (m *Claude) StreamGenerateContent(ctx context.Context, request *types.LLMRequest) iter.Seq2[*types.LLMResponse, error] {
	return func(yield func(*types.LLMResponse, error) bool) {
		// Convert to Anthropic format
		messages := make([]anthropic.MessageParam, len(request.Contents))
		for i, content := range request.Contents {
			messages[i] = m.contentToMessageParam(ctx, content)
		}

		// Prepare parameters
		params := anthropic.MessageNewParams{
			Model:     anthropic.Model(m.modelName),
			Messages:  messages,
			MaxTokens: m.maxTokens,
		}

		// Apply generation config if provided
		if config := request.Config; config != nil {
			// MaxOutputTokens is an int32 directly, not a pointer
			if config.MaxOutputTokens > 0 {
				params.MaxTokens = int64(config.MaxOutputTokens)
			}

			if config.Temperature != nil {
				params.Temperature = anthropic.Float(float64(*config.Temperature))
			}

			if config.TopK != nil {
				params.TopK = anthropic.Int(int64(*config.TopK))
			}

			if config.TopP != nil {
				params.TopP = anthropic.Float(float64(*config.TopP))
			}

			if config.SystemInstruction != nil {
				for _, instruction := range config.SystemInstruction.Parts {
					params.System = append(params.System, anthropic.TextBlockParam{
						Text: instruction.Text,
					})
				}
			}

			// Add tools if provided
			if len(config.Tools) > 0 && config.Tools[0].FunctionDeclarations != nil {
				tools := make([]anthropic.ToolUnionParam, 0, len(config.Tools[0].FunctionDeclarations))
				for _, funcDeclarations := range config.Tools[0].FunctionDeclarations {
					toolUnion, err := m.funcDeclarationToToolParam(funcDeclarations)
					if err != nil {
						if !yield(nil, err) {
							return
						}
					}
					tools = append(tools, toolUnion)
				}
				params.Tools = tools
			}
		}

		if len(request.ToolMap) > 0 {
			toolchoice := anthropic.ToolChoiceUnionParam{
				OfAuto: &anthropic.ToolChoiceAutoParam{
					DisableParallelToolUse: anthropic.Bool(false),
				},
			}
			params.ToolChoice = toolchoice
		}

		// Make streaming API call - stream parameter is added by the method
		stream := m.anthropicClient.Messages.NewStreaming(ctx, params)

		if ctx.Err() != nil || stream == nil {
			return
		}

		message := anthropic.Message{}
		for stream.Next() {
			// Accumulate the response
			llmResp := stream.Current()
			if err := message.Accumulate(llmResp); err != nil {
				m.logger.ErrorContext(ctx, "accumulating message", slog.Any("err", err))
				if !yield(nil, err) {
					return
				}
			}

			if message.StopReason == anthropic.StopReasonEndTurn {
				return
			}

			// Create partial response
			var parts []*genai.Part
			partial := true

			// Process based on event type
			switch messageStreamEvent := llmResp.AsAny().(type) {
			case anthropic.MessageStartEvent:
				// no-op
			case anthropic.ContentBlockStartEvent:
				// no-op
			case anthropic.ContentBlockDeltaEvent:
				// Extract delta from content block delta
				switch delta := messageStreamEvent.Delta.AsAny().(type) {
				case anthropic.TextDelta:
					parts = append(parts, genai.NewPartFromText(delta.Text))
				}
			case anthropic.ContentBlockStopEvent:
				// no-op
			}

			for _, mcontent := range message.Content {
				part, err := m.contentBlockToPart(mcontent)
				if err != nil {
					if !yield(nil, err) {
						return
					}
				}
				if part.Text != "" {
					parts = append(parts, genai.NewPartFromText(part.Text))
					partial = false
				}
			}

			// Only return a response if we have parts
			if len(parts) > 0 {
				response := &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{
						{
							Content: &genai.Content{
								Role:  RoleAssistant,
								Parts: parts,
							},
						},
					},
				}
				resp := types.CreateLLMResponse(response)
				if partial {
					resp.WithPartial(true)
				}
				if !yield(resp, nil) {
					return
				}
			}
		}
		if err := stream.Err(); err != nil {
			if !yield(nil, err) {
				return
			}
		}
	}
}
