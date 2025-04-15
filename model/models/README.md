# Model Implementations

This package provides implementations of various language models for use with the ADK Go framework.

## Overview

The model implementations in this package are based on the [Google ADK Python](https://github.com/google/adk-python) 
repository's model implementations, ported to Go and adapted to the ADK Go framework.

## Models

The following model providers are supported:

- **Google** (Gemini)
- **OpenAI** (GPT)
- **Anthropic** (Claude)
- **Mock** (for testing)

## Architecture

### Registry Pattern

The model implementations use a registry pattern for dynamic model selection:

- Models are registered with pattern-based matching (regex)
- Models can be instantiated by ID or provider
- The registry maintains a cache of model instances

### Base Model

All models extend a common `BaseModel` implementation that provides:

- Common model interface implementation
- Capability management
- Default implementations for most methods

### Model Capabilities

Models declare their capabilities such as:

- Tool calling
- Vision processing
- Streaming support
- JSON output
- Function calling

## Usage

### Creating a Model

```go
// By Model ID
model, err := models.NewModelFromID("gemini-1.5-flash")

// By Provider
model, err := models.NewModelFromProvider(model.ModelProviderGoogle)

// Using Default Registry
model, err := models.GetModel("claude-3-sonnet-20240229")
```

### Model Operations

```go
// Simple Generation
resp, err := model.Generate(ctx, messages)

// Generation with Options
opts := model.GenerateOptions{
    Temperature: 0.7, 
    MaxTokens: 1000,
}
resp, err := model.GenerateWithOptions(ctx, messages, opts)

// Tool-based Generation
resp, err := model.GenerateWithTools(ctx, messages, tools)

// Streaming Generation
err := model.GenerateStream(ctx, messages, func(chunk message.Message) {
    // Process each chunk as it arrives
})
```

## Testing

The package includes a `MockModel` implementation for testing purposes, which allows:

- Setting predefined responses for specific inputs
- Injecting errors
- Configuring tool call responses
- Simulating streaming responses