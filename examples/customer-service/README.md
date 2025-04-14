# Customer Service Agent Example

This example demonstrates a customer service agent for Cymbal Home & Garden (a fictional company) using the Agent Development Kit Go implementation.

## Features

- Interactive CLI-based customer service agent
- Integration with Google's Gemini model
- Tool-based system for product searches, order lookups, and appointment scheduling
- Observability with logging, tracing, and metrics

## Prerequisites

- Go 1.24 or higher
- Google API key with access to Gemini models

## Getting Started

1. Set your Google API key as an environment variable:

```bash
export GOOGLE_API_KEY=your_api_key_here
```

2. Run the agent:

```bash
go run main.go
```

3. Interact with the agent by typing messages at the prompt. The agent can help with:
   - Product searches
   - Order lookups
   - Scheduling appointments

4. Type 'exit' or 'quit' to end the conversation.

## Environment Variables

- `GOOGLE_API_KEY`: Your Google API key for accessing Gemini models

## Tool Descriptions

- **Product Search**: Search the store's inventory for products by keyword and category
- **Order Lookup**: Look up order details using an order ID
- **Appointment Scheduling**: Schedule consultations or service appointments

## Implementation Details

This example implements a single agent pattern using:

- A conversational interface through the command line
- Tool-based pattern for domain-specific functionality
- Mock backend services (product database, order system, appointment scheduler)
