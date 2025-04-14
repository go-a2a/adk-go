# Data Science Multi-Agent System Example

This example demonstrates a multi-agent system for data science tasks using the Agent Development Kit Go implementation.

## Features

- Multi-agent system with specialized data science roles
- Shared memory for agent communication
- Interactive CLI-based interface
- Integration with Google's Gemini model
- Simulated data analysis workflow

## Prerequisites

- Go 1.24 or higher
- Google API key with access to Gemini models

## Getting Started

1. Set your Google API key as an environment variable:

```bash
export GOOGLE_API_KEY=your_api_key_here
```

2. Run the agent system:

```bash
go run main.go
```

3. Interact with the system by typing data analysis requests. For example:
   - "Analyze the customer satisfaction data and identify key factors influencing scores"
   - "Find correlations between marketing spend and sales performance"
   - "Segment our customer base and provide insights about each group"

4. Type 'exit' or 'quit' to end the conversation.

## Environment Variables

- `GOOGLE_API_KEY`: Your Google API key for accessing Gemini models

## Agent Descriptions

### Coordinator
Manages the workflow, understands user requests, and delegates tasks to specialists.

### Data Analyst
Performs data cleaning, preprocessing, and exploratory analysis.

### Statistician
Conducts statistical analysis, hypothesis testing, and modeling.

### Visualizer
Creates data visualizations and charts for better understanding.

### Interpreter
Provides business insights and actionable recommendations based on results.

## Implementation Details

This example implements a multi-agent system with:

- A coordinator agent that manages the workflow
- Four specialist agents with specific data science roles
- A shared memory system for communication between agents
- Tool-based pattern for domain-specific functionality
- Simulated data analysis functions (in a real application, these would connect to actual data science libraries)
