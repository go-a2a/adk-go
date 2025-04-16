# ADK-Go: Agent Development Kit for Go

> [!IMPORTANT]
> This project is in the alpha stage.
>
> Flags, configuration, behavior, and design may change significantly.

[![Go Reference](https://pkg.go.dev/badge/github.com/go-a2a/adk-go.svg)](https://pkg.go.dev/github.com/go-a2a/adk-go)
[![Go](https://github.com/go-a2a/adk-go/actions/workflows/go.yml/badge.svg)](https://github.com/go-a2a/adk-go/actions/workflows/test.yml)

An open-source, code-first Go toolkit for building, evaluating, and deploying sophisticated AI agents with flexibility and control.

This is a Go implementation of the [Agent Development Kit (ADK)](https://github.com/google/adk-python), a toolkit for building, evaluating, and deploying sophisticated AI agents. ADK-Go follows the same architectural principles as the Python implementation, but with Go's strengths of type safety, performance, and concurrency.

## Features

- Code-first agent development in Go with modern architecture
- Support for both single agents and multi-agent systems
- Specialized agent types (Base, LLM, Loop, Sequential, Parallel)
- Flow-based message processing architecture
- Modular architecture for flexible agent composition
- Built-in tool integrations with pluggable registry
- Type-safe interfaces for agent development
- Full observability with OpenTelemetry integration for tracing, metrics, and logging
- High-performance JSON processing with Bytedance Sonic
- Model support for Google, OpenAI, and Anthropic
- Async tool support with caching
- Memory systems (in-memory, vector, knowledge graph)
- Session management with state tracking

## Installation

```bash
go get github.com/go-a2a/adk-go@latest
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

## Project Structure

- `agent`: Core agent implementations (BaseAgent, Agent, LLMAgent, LoopAgent, SequentialAgent, ParallelAgent)
- `artifacts`: Artifact storage for files and binary data
- `auth`: Authentication and authorization mechanisms
- `codeexecutor`: Code execution environments and utilities
- `evaluation`: Agent evaluation and benchmarking tools
- `event`: Event system for tracking agent interactions
- `flow`: Flow-based processing architecture with processors
    - `flow/llmflow`: Specialized flows for LLM-based interactions
- `memory`: Memory systems (in-memory, vector, knowledge graph)
- `message`: Message types and utilities for agent communication
- `model`: Model interfaces and definitions for LLM integration
    - `model/models`: Model implementations for various LLM providers
- `observability`: Tracing, metrics, and logging utilities
- `planner`: Planning components for agent task execution
- `runner`: Agent execution utilities for orchestrating agent interactions
- `session`: Session management for persistent conversations
- `tool`: Tool interfaces and implementations for extending agent capabilities
    - `tool/tools`: Common tool implementations

## Tools

The library includes various tool implementations:

- `agent_tool`: Tool for delegating to sub-agents
- `function_tool`: Tool for executing custom functions
- `google_search`: Web search tool
- `load_web_page`: Web page loading tool
- `memory_tool`: Tool for accessing memory systems
- `openapi_tool`: Tool for integrating OpenAPI services
- `user_choice_tool`: Tool for interactive decision making
- Custom tool support via `tool.BaseTool`
- Async tool support via `tool.AsyncTool`
- Tool registry for dynamic tool loading

## Memory Systems

ADK-Go provides multiple memory systems:

- `in_memory_service`: Simple in-memory storage
- `vector_memory_service`: Vector-based memory for semantic retrieval
- `knowledge_graph_service`: Graph-based memory for structured knowledge

## Model Providers

ADK-Go supports multiple model providers:

- Google Gemini (via official Google Generative AI SDK)
- Anthropic (Claude models)
- OpenAI (GPT models)
- Custom model support via `model.Model` interface

## Usage Examples

> [!NOTE]
> See [examples](./examples) for detailed and fully working example codes.

### Single Agent

```go
package main

import (
	"context"
	"log/slog"
	"os"
	
	"github.com/go-a2a/adk-go/agent"
	"github.com/go-a2a/adk-go/models"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/runner"
	"github.com/go-a2a/adk-go/tool/tools"
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

### Multi-Agent Systems with Specialized Agents

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

### Loop Agent for Iterative Processing

```go
// Create a LoopAgent for complex reasoning
continueCondition := func(ctx context.Context, msg message.Message) (bool, error) {
    // Continue until "FINAL ANSWER:" appears in the response
    return !strings.Contains(msg.Content, "FINAL ANSWER:"), nil
}

reasoningAgent := agent.NewLoopAgent(
    "ReasoningAgent",
    model,
    "You are a reasoning agent that solves complex problems step-by-step. Continue thinking and refining your answer until you reach a final conclusion, then prefix your final answer with 'FINAL ANSWER:'.",
    "Agent for step-by-step reasoning",
    []tool.Tool{calculatorTool, webSearchTool},
    5, // Maximum 5 iterations
    continueCondition,
)

// Use the agent
response, err := runner.NewRunner(reasoningAgent).Run(
    context.Background(), 
    "Solve this problem: If a train travels at 60 mph for 2 hours then at 30 mph for 1 hour, what is the average speed?",
)
```

### Sequential Agent for Multi-Step Processing

```go
// Create agents for each step in a process
researchAgent := agent.NewLlmAgent(
    "ResearchAgent",
    model,
    "Research the topic thoroughly and provide key facts.",
    "Finds information",
    []tool.Tool{searchTool, webTool},
)

analysisAgent := agent.NewLlmAgent(
    "AnalysisAgent",
    model,
    "Analyze the information and identify patterns and insights.",
    "Analyzes information",
    nil,
)

summaryAgent := agent.NewLlmAgent(
    "SummaryAgent",
    model,
    "Create a concise summary of the analysis.",
    "Summarizes content",
    nil,
)

// Create sequential pipeline
reportGenerator := agent.NewSequentialAgent(
    "ReportGenerator",
    "Generates comprehensive reports through a multi-step process",
    researchAgent, analysisAgent, summaryAgent,
)

// Use the sequential agent
response, err := runner.NewRunner(reportGenerator).Run(
    context.Background(),
    "Create a report about renewable energy trends in 2024",
)
```

### Parallel Agent for Concurrent Processing

```go
// Define a custom result aggregator 
resultAggregator := func(ctx context.Context, results []message.Message) (message.Message, error) {
    var combinedContent strings.Builder
    
    combinedContent.WriteString("# Combined Analysis\n\n")
    
    for i, result := range results {
        combinedContent.WriteString(fmt.Sprintf("## Expert %d Analysis\n\n", i+1))
        combinedContent.WriteString(result.Content)
        combinedContent.WriteString("\n\n")
    }
    
    return message.NewAssistantMessage(combinedContent.String()), nil
}

// Create specialized expert agents
financialAgent := agent.NewLlmAgent(
    "FinancialExpert",
    model,
    "Analyze this company from a financial perspective.",
    "Financial analysis expert",
    nil,
)

marketingAgent := agent.NewLlmAgent(
    "MarketingExpert", 
    model,
    "Analyze this company's marketing strategy.",
    "Marketing analysis expert",
    nil,
)

techAgent := agent.NewLlmAgent(
    "TechnicalExpert",
    model,
    "Analyze this company's technical infrastructure and innovation.",
    "Technical analysis expert",
    nil,
)

// Create parallel agent with custom aggregator
companyAnalyzer := agent.NewParallelAgent(
    "CompanyAnalyzer",
    "Analyzes companies from multiple perspectives concurrently",
    resultAggregator,
    financialAgent, marketingAgent, techAgent,
)

// Use the parallel agent
response, err := runner.NewRunner(companyAnalyzer).Run(
    context.Background(),
    "Analyze Apple Inc. as a company in 2024",
)
```

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](./LICENSE) file for details.
