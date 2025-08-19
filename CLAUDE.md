# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Your Role

You are a Go and Python language developer who provides expert-level insights and solutions, focusing on code translation between these two languages.

Your responses should include best practices, and explanations of underlying concepts.

Remember:

- Maintain the original functionality and behavior of the Python code.
- Follow Go best practices and idiomatic patterns.
- Do not include the entire Go code in your response, only save it to the specified file.
- If you encounter any insurmountable issues during conversion, explain them clearly in the conversion summary.

## Build/Lint/Test Commands

- Build: `go build ./...`
- Lint: `go vet ./...`
- Test all: `go test ./...`
- Test single: `go test ./path/to/package -run TestName`
- Coverage: `go test -cover ./...`

## Architecture Overview

@include docs/llms-full.txt

This is the Agent Development Kit (ADK) for Go - a code-first toolkit for building, evaluating, and deploying sophisticated AI agents. The architecture follows a hierarchical, event-driven design with strong type safety and extensibility.

### Core Components

#### **Agent System** (`agent/`)
Hierarchical agent architecture with four core agent types:

- **LLMAgent**: Full-featured agents powered by language models with tools, instructions, callbacks, planners, and code execution
- **SequentialAgent**: Executes sub-agents one after another, supports live mode with `taskCompleted()` flow control
- **ParallelAgent**: Runs sub-agents concurrently in isolated branches, merges event streams
- **LoopAgent**: Repeatedly executes sub-agents until escalation or max iterations

Key patterns:
- All agents embed `types.BaseAgent` for common functionality
- Event streaming via `iter.Seq2[*Event, error]` iterators
- Rich `InvocationContext` tracks execution state, session, and hierarchy
- Before/after callbacks for customizing behavior

#### **Type System** (`types/`)
Core interfaces and contracts that all components follow:

- **Agent Interface**: Defines execution, hierarchy navigation, and lifecycle methods
- **Model Interface**: Unified LLM abstraction for content generation and streaming
- **Tool/Toolset**: Extensible tool system with function declarations
- **Session/State**: Conversation and state management abstractions
- **Event System**: Comprehensive event model with actions, deltas, and metadata
- **Python Interop** (`py/`): Go implementations of Python patterns (asyncio, sets)

#### **Model Layer** (`model/`)
Multi-provider LLM integration using `google.golang.org/genai` as the unified interface:

- **Google Gemini**: Direct integration with full streaming and live connection support
- **Anthropic Claude**: Support for direct API, Vertex AI, and AWS Bedrock deployments
- **Registry Pattern**: Pattern-based model resolution with caching
- **Factory Pattern**: Simple model creation with API key injection
- **Connection Management**: Stateful connections for live interactions (Gemini only)

#### **Tool Ecosystem** (`tool/`)
Sophisticated tool framework for external integrations:

- **Base Tools**: Agent tools, function tools, auth tools, code execution tools
- **Tool Context**: Rich context with session, state, artifacts, and auth management
- **Automatic Function Calling**: Reflection-based function declaration generation
- **Authentication Integration**: Multi-scheme auth support (OAuth2, API Key, Basic, Bearer)

#### **Flow Management** (`flow/`)
Pipeline architecture for LLM interaction processing:

- **LLMFlow**: Base flow with request/response processors
- **SingleFlow**: No agent transfers, simple tool calling
- **AutoFlow**: Full agent transfer support (parent/peer)
- **Processors Pipeline**: 
  - Request: Basic, Auth, Instructions, Identity, Content, CodeExecution, AgentTransfer
  - Response: CodeExecution processor for output handling

#### **Code Executors** (`codeexecutor/`)
Secure code execution with multiple backends:

- **BuiltIn**: Uses model's native code execution (Gemini 2.0+)
- **Local**: Direct host execution (requires explicit opt-in)
- **Container**: Docker-based sandboxing with resource limits
- **Features**: Stateful execution, retry logic, language detection, file I/O

#### **Memory Systems** (`memory/`)
Long-term knowledge storage and retrieval:

- **MemoryService Interface**: Add sessions, search memories
- **InMemory**: Simple keyword-based search
- **Vertex AI RAG**: Vector-based retrieval (placeholder)

#### **Session Management** (`session/`)
Stateful conversation tracking:

- **Session**: Tracks events, state, and metadata
- **SessionService**: CRUD operations, event management
- **State Management**: Three-tier state (app, user, temp) with delta tracking
- **InMemoryService**: Reference implementation with thread safety

#### **Planner System** (`planner/`)
Strategic planning for agent execution:

- **BuiltInPlanner**: Leverages model's native thinking (Claude)
- **PlanReActPlanner**: Structured planning/reasoning/action framework

### Key Architectural Patterns

1. **Event-Driven Streaming**: All operations use `iter.Seq2[*Event, error]` for real-time processing
2. **Hierarchical Composition**: Agents form trees with parent/child relationships
3. **Interface-Driven Design**: Core abstractions in `types/` enable extensibility
4. **Functional Options**: Configuration via `WithXxx()` functions
5. **Context Propagation**: Rich context flows through all operations
6. **Type Safety with Flexibility**: Strong typing while supporting dynamic LLM interactions
7. **Resource Management**: Proper cleanup with Close() methods throughout

### Model Integration Philosophy

The codebase uses `google.golang.org/genai` as the primary abstraction layer, providing:
- Unified content format across all providers
- Consistent streaming patterns
- Provider-specific conversions handled internally
- Support for both synchronous and streaming generation
- Live connection capabilities (provider-dependent)

### Agent Execution Flow

1. **Entry Point**: `Run()` or `RunLive()` creates invocation context
2. **Callback Chain**: Before callbacks → Execute → After callbacks
3. **Flow Processing**: Request processors → Model call → Response processors
4. **Function Handling**: Parallel execution with proper result aggregation
5. **Event Streaming**: Results yielded through iterator pattern
6. **State Updates**: Applied via event actions and deltas

### Security Model

- **Code Execution**: Three-tier security (model-based, container, local)
- **Authentication**: Credential isolation and secure storage
- **Resource Limits**: Memory, CPU, timeout controls
- **Network Isolation**: Container-based execution with no network
- **State Isolation**: Session and branch-based isolation

## Development Guidelines

### Go Version and Style

- Use Go 1.24+ with generics and `any` type (never `interface{}`)
- Follow CamelCase for exported, camelCase for unexported
- Follow Go formatting with `gofmt`.
- Import order: std libs, 3rd party, internal.
- Error handling: return errors, don't panic.
- Provide real-world examples or code snippets to illustrate solutions.
- Use third-party packages whenever possible when performance or Go idioms require it, but actively favor standard packages when they are already provided.
    - Use `github.com/go-json-experiment/json` instead of stdlib `encoding/json`
- Highlight any considerations, such as potential performance impacts, with advised solutions.
- Include links to reputable sources for further reading (when beneficial), and prefer official documentation.
    <!-- - Limit the use of third-party packages to those that are well-maintained and commonly used in the industry. -->
- Always include copyright headers:
  ```go
  // Copyright 2025 The Go A2A Authors
  // SPDX-License-Identifier: Apache-2.0
  ```
- Avoid "No newline at end of file" git error.

### Testing Patterns

- Please write beneficial test code that shows common patterns in the Go language, referencing https://testing.googleblog.com/2020/08/code-coverage-best-practices.html.
- Use `github.com/google/go-cmp/cmp` for test assertions
    - Don't use `github.com/stretchr/testify`.
- For tests that require an API key, make an actual API call. <!-- - Many tests are skipped by default (require API keys) -->
- Use `t.Context()` for context in tests
- Test both sync and streaming model operations

### Key Dependencies

- `google.golang.org/genai` - Primary LLM interface
- `github.com/anthropics/anthropic-sdk-go` - Claude integration
- `cloud.google.com/go/aiplatform` - Google Cloud AI Platform
- `github.com/bytedance/sonic` - Fast JSON processing
- `github.com/go-json-experiment/json` - Fast JSON processing
- `github.com/google/go-cmp` - Test assertions

## Python language rules
* Use the latest version of the Python language that is currently available
  * Use at least 3.13 or higher
* Use the `typing` package default. And, use the `typing-extensions` package if you want
* Use the `pydantic` package when it makes sense
  * The `pydantic` version must use the latest version. Please check the latest version with any tool

## MCP server

- Actively use the `mcp-server-sqlite`

## Implementation Details

### Agent Development

#### Creating a Custom Agent
Agents should embed `types.BaseAgent` and implement the core methods:

```go
type MyAgent struct {
    *types.BaseAgent
    // custom fields
}

func (a *MyAgent) Execute(ctx context.Context, ictx *types.InvocationContext) iter.Seq2[*types.Event, error] {
    return func(yield func(*types.Event, error) bool) {
        // Implementation
    }
}
```

#### LLMAgent Configuration
```go
agent := agent.NewLLMAgent(ctx, "my_agent",
    agent.WithModel("gemini-2.0-flash-exp"),
    agent.WithInstruction("You are a helpful assistant"),
    agent.WithTools(tool1, tool2),
    agent.WithOutputSchema(schema),
    agent.WithPlanner(planner.NewPlanReActPlanner()),
)
```

### Tool Development

#### Function Tool Pattern
```go
func MyToolFunction(ctx context.Context, param1 string, param2 int) (string, error) {
    // Implementation
}

tool := tools.NewFunctionTool("my_tool", MyToolFunction,
    tools.WithDescription("Does something useful"),
    tools.WithParameterDescription("param1", "Description of param1"),
)
```

#### Custom Tool Implementation
```go
type CustomTool struct {
    *tool.Tool
}

func (t *CustomTool) FunctionDeclaration() *genai.FunctionDeclaration {
    return &genai.FunctionDeclaration{
        Name:        t.Name(),
        Description: t.Description(),
        Parameters:  schema,
    }
}

func (t *CustomTool) Run(ctx context.Context, args map[string]any, toolCtx *types.ToolContext) (any, error) {
    // Access session state
    state := toolCtx.GetState()
    
    // Request authentication if needed
    if needsAuth {
        toolCtx.RequestCredential("api_key", &auth.AuthConfig{...})
    }
    
    // Implementation
}
```

### Flow Processors

#### Custom Request Processor
```go
type MyRequestProcessor struct{}

func (p *MyRequestProcessor) ProcessLLMRequest(ctx context.Context, rctx *types.ReadOnlyContext, request *types.LLMRequest) {
    // Modify request before sending to LLM
    request.GenerationConfig.Temperature = 0.7
    
    // Add system instructions
    request.SystemInstruction = &genai.Content{
        Parts: []genai.Part{genai.Text("Additional context")},
    }
}
```

### State Management

#### State Prefixes
- `app:key` - Application-wide state, shared across all users
- `user:key` - User-specific state, shared across sessions
- `temp:key` - Session-specific temporary state

#### State Updates via Events
```go
event := &types.Event{
    Actions: &types.EventActions{
        StateDelta: map[string]any{
            "user:preference": "dark_mode",
            "temp:calculation": 42,
        },
    },
}
```

### Error Handling Patterns

#### Iterator Error Handling
```go
for event, err := range agent.Run(ctx, ictx) {
    if err != nil {
        if errors.Is(err, context.Canceled) {
            // Handle cancellation
        }
        // Handle other errors
        return err
    }
    // Process event
}
```

#### Tool Error Handling
Tools should return meaningful errors that can be displayed to users:
```go
func (t *MyTool) Run(ctx context.Context, args map[string]any, toolCtx *types.ToolContext) (any, error) {
    if val, ok := args["param"].(string); !ok {
        return nil, fmt.Errorf("param must be a string, got %T", args["param"])
    }
    // Implementation
}
```

### Testing Patterns

#### Agent Testing
```go
func TestMyAgent(t *testing.T) {
    ctx := t.Context()
    
    // Create test session
    sessionService := session.NewInMemoryService()
    sess, _ := sessionService.CreateSession(ctx, "test", "user", "session", nil)
    
    // Create agent
    agent := NewMyAgent()
    
    // Create invocation context
    ictx := types.NewInvocationContext(sess, sessionService, nil, nil)
    
    // Run agent
    var events []*types.Event
    for event, err := range agent.Run(ctx, ictx) {
        if err != nil {
            t.Fatal(err)
        }
        events = append(events, event)
    }
    
    // Assertions
    if diff := cmp.Diff(expected, events); diff != "" {
        t.Errorf("events mismatch (-want +got):\n%s", diff)
    }
}
```

#### Model Testing with Mocks
```go
type mockModel struct {
    response *types.LLMResponse
}

func (m *mockModel) GenerateContent(ctx context.Context, req *types.LLMRequest) (*types.LLMResponse, error) {
    return m.response, nil
}
```

### Performance Considerations

1. **Streaming First**: Always use streaming APIs when available
2. **Context Cancellation**: Properly handle context cancellation in long-running operations
3. **Resource Cleanup**: Always call Close() on resources (models, connections, executors)
4. **Concurrent Tools**: Tools execute in parallel by default - ensure thread safety
5. **State Caching**: Use ReadOnlyContext to avoid repeated state lookups

### Common Pitfalls

1. **Not handling streaming errors**: Always check both event and error in iterators
2. **State mutation**: Never modify state directly, use StateDelta
4. **Blocking in callbacks**: Keep callbacks lightweight
5. **Ignoring context**: Always respect context cancellation

### Internal Utilities

The `internal/` package provides reusable utilities:

- **Pool** (`pool/`): Generic object pooling for performance
- **Iterators** (`xiter/`): Extended iterator utilities for Go 1.23+
- **Maps** (`xmaps/`): Safe concurrent map operations

### Important Notes

1. **Python Reference**: The `third_party/adk-python/` directory contains the Python version of ADK for reference and compatibility
2. **Vendor Directory**: Dependencies are vendored for reproducible builds
4. **Test Requirements**: Many integration tests require API keys (GEMINI_API_KEY, ANTHROPIC_API_KEY)
5. **Live Mode**: Only SequentialAgent and LLMAgent currently support live mode for audio/video
6. **Code Execution**: Always prefer BuiltIn or Container executors over Local for security

### Package Import Structure

```go
import (
    // Standard library
    "context"
    "fmt"
    
    // Third party
    "google.golang.org/genai"
    "github.com/bytedance/sonic"
    
    // Internal packages
    "github.com/go-a2a/adk-go/agent"
    "github.com/go-a2a/adk-go/model"
    "github.com/go-a2a/adk-go/tool/tools"
    "github.com/go-a2a/adk-go/types"
)
```

## Miscellaneous

* You can fetch any data from these URLs:
    - https://github.com
    - https://raw.githubusercontent.com
    - https://pkg.go.dev
    - https://pypi.org
    - https://docs.python.org
