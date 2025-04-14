# ADK-Go Examples

This directory contains example implementations of AI agents using the Go Agent Development Kit (ADK-Go). These examples demonstrate different agent architectures and use cases, inspired by the [Google ADK Samples](https://github.com/google/adk-samples).

## Available Examples

### [Customer Service Agent](./customer-service/)

A single-agent implementation of a customer service assistant for a fictional home and garden store (Cymbal Home & Garden).

**Features:**
- Interactive CLI-based customer service agent
- Product search, order lookup, and appointment scheduling tools
- Simulated backend services

### [Data Science Multi-Agent System](./data-science/)

A multi-agent system for data science tasks with specialized agents for different parts of the analysis workflow.

**Features:**
- Coordinator agent that manages the workflow
- Specialized agents for data analysis, statistics, visualization, and interpretation
- Shared memory system for agent communication
- Simulated data science tools

### [Retrieval-Augmented Generation (RAG) Agent](./rag/)

A RAG agent that can answer questions based on a document repository.

**Features:**
- Document repository with search capabilities
- Ability to upload and retrieve documents
- Keyword-based search with relevant snippets
- Document metadata support

## Running the Examples

Each example has its own `go.mod` file and can be run independently. Navigate to the example directory and run:

```bash
go run main.go
```

Most examples require a Google API key for the Gemini model, which should be set as an environment variable:

```bash
export GOOGLE_API_KEY=your_api_key_here
```

## Prerequisites

- Go 1.24 or higher
- Google API key for Gemini models (for most examples)

## Implementation Notes

These examples are designed to demonstrate different agent architectures and use cases. They use the `go-a2a/adk-go` library to interface with language models, tools, and agent frameworks.

All examples include observability support with logging, tracing, and metrics using OpenTelemetry.

For more details on a specific example, see the README file in the example's directory.
