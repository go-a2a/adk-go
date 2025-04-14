# Retrieval-Augmented Generation (RAG) Agent Example

This example demonstrates a RAG (Retrieval-Augmented Generation) agent for answering questions about documents stored in a knowledge base using the Agent Development Kit Go implementation.

## Features

- Document repository with search capabilities
- Retrieval-augmented generation workflow
- Interactive CLI-based interface
- Integration with Google's Gemini model
- Document upload functionality

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

3. Interact with the agent by asking questions about documents in its knowledge base. Examples:
   - "What are the fundamentals of machine learning?"
   - "Tell me about natural language processing"
   - "What is artificial intelligence?"

4. You can also upload new documents with commands like:
   - "Upload a document about deep learning with the following content: [your content here]"

5. Type 'exit' or 'quit' to end the conversation.

## Environment Variables

- `GOOGLE_API_KEY`: Your Google API key for accessing Gemini models

## Document Repository

The example includes a simple in-memory document repository with these initial documents:

- Introduction to Artificial Intelligence
- Machine Learning Fundamentals
- Natural Language Processing Overview

## Tool Descriptions

- **Search Documents**: Search for documents containing specific keywords
- **Get Document**: Retrieve a document by its ID
- **Upload Document**: Add a new document to the repository

## Implementation Details

This example implements a RAG pattern using:

- In-memory artifact service for document storage
- Basic search functionality with relevance scoring
- Tool-based approach for document retrieval and search
- Text formatting for improved readability
- Basic document metadata support
