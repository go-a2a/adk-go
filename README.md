# ADK-Go: Agent Development Kit for Go

An open-source, code-first Go toolkit for building, evaluating, and deploying sophisticated AI agents with flexibility and control.

This is a Go implementation of the [Agent Development Kit (ADK)](https://github.com/google/adk-python), a toolkit for building, evaluating, and deploying sophisticated AI agents.

## Features

- Code-first agent development in Go with modern architecture
- Support for both single agents and multi-agent systems
- Modular architecture for flexible agent composition
- Built-in tool integrations
- Type-safe interfaces for agent development
- Full observability with OpenTelemetry integration for tracing, metrics, and logging
- High-performance JSON processing with Bytedance Sonic
- Official Google Generative AI SDK integration
- Async tool support with caching

## Installation

```bash
go get github.com/go-a2a/adk-go
```

## Key Design Principles

### Performance

- Uses Bytedance Sonic for fast JSON serialization and deserialization
- Efficient memory usage with smart caching strategies
- Optimized object allocation and reuse
- Configurable concurrency limits

### Observability

- Complete OpenTelemetry integration with tracing, metrics, and logging
- Structured logging with log/slog
- Detailed performance metrics
- Request/response telemetry

### Type Safety

- Strong Go typing throughout
- Clear interfaces
- Comprehensive error handling
- Input validation

### Extensibility

- Modular design
- Plugin architecture for tools
- Multiple model provider support
- Custom agent support

## Usage Examples

### Single Agent

```go
package main

import (
	"context"
	"log/slog"
	"os"
	
	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/models"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/runner"
	"github.com/go-a2a/adk-go/pkg/tools"
)

func main() {
	// Setup observability
	observability.SetupLogger(observability.LoggerOptions{
		Level: observability.LevelInfo,
		Writer: os.Stdout,
	})
	
	shutdownTracer, _ := observability.InitTracer(context.Background(), "my-app")
	defer shutdownTracer(context.Background())
	
	// Initialize model
	apiKey := os.Getenv("GEMINI_API_KEY")
	model, err := models.NewGeminiModel("gemini-2.0-flash", apiKey)
	if err != nil {
		slog.Error("Failed to create model", slog.Any("error", err))
		os.Exit(1)
	}
	
	// Create tools
	searchTool := tools.NewGoogleSearchTool()
	webTool := tools.NewLoadWebPageTool()
	
	// Create agent
	assistant := agent.NewLlmAgent(
		"search_assistant",
		model,
		"You are a helpful assistant. Answer user questions using search when needed.",
		"An assistant that can search the web.",
		[]tool.Tool{searchTool, webTool},
	)
	
	// Create runner and execute
	agentRunner := runner.NewRunner(assistant)
	response, err := agentRunner.Run(context.Background(), "Tell me about Go programming")
	if err != nil {
		slog.Error("Error running agent", slog.Any("error", err))
		os.Exit(1)
	}
	
	slog.Info("Assistant response", slog.String("content", response.Content))
}
```

### Multi-Agent System

```go
// Create specialized agents
researchAgent := agent.NewLlmAgent(
	"ResearchAgent",
	model,
	"You are a research agent that finds information.",
	"Specialized for research tasks",
	[]tool.Tool{searchTool, webTool},
)

creativeAgent := agent.NewLlmAgent(
	"CreativeAgent", 
	model,
	"You are a creative agent that generates original ideas.",
	"Specialized for creative tasks",
	nil,
)

// Create a custom agent for analytics
analyticsAgent := agent.NewBaseAgent(
	"AnalyticsAgent",
	"Handles data analysis",
	nil,
	func(ctx context.Context, msg message.Message) (message.Message, error) {
		// Custom analytics implementation
		return message.NewAssistantMessage("Analytics result..."), nil
	},
)

// Create coordinator agent
coordinator := agent.NewLlmAgent(
	"Coordinator",
	model,
	"You route tasks to the appropriate specialized agents.",
	"Coordinates between different agents",
	nil,
)

// Connect agents
coordinator.WithSubAgents(researchAgent, creativeAgent, analyticsAgent)
```

## Project Structure

- `pkg/agent`: Core agent implementations
- `pkg/message`: Message types and utilities
- `pkg/model`: Model interfaces and definitions
- `pkg/tool`: Tool interfaces and implementations
- `pkg/runner`: Agent execution utilities
- `pkg/models`: Model implementations for various LLM providers
- `pkg/tools`: Common tool implementations
- `pkg/observability`: Tracing, metrics, and logging utilities
- `examples`: Example applications using ADK-Go

## Tools

The library includes various tool implementations:

- `google_search`: Web search tool
- `load_web_page`: Web page loading tool
- Custom tool support via `tool.BaseTool`
- Async tool support via `tool.AsyncTool`

## Model Providers

ADK-Go supports multiple model providers:

- Google Gemini (via official Google Generative AI SDK)
- (More coming soon)

## License

Apache 2.0
