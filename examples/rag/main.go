// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/bytedance/sonic"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/artifacts"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/model/models"
	"github.com/go-a2a/adk-go/pkg/observability"
	"github.com/go-a2a/adk-go/pkg/tool"
)

func main() {
	ctx := context.Background()

	// Initialize observability
	observability.InitLogging("rag-agent", slog.LevelDebug)
	observability.InitTracing(ctx, "rag-agent")
	observability.InitMetrics(ctx, "rag-agent")

	// Set up the model
	googleModel, err := models.NewGoogleModel("gemini-1.5-pro", os.Getenv("GOOGLE_API_KEY"), "")
	if err != nil {
		panic(fmt.Sprintf("Failed to create model: %v", err))
	}

	// Create artifact service for document storage
	artifactService := artifacts.NewInMemoryArtifactService()

	// Initialize the document storage with some example documents
	initializeDocumentStore(ctx, artifactService)

	// Create the tools
	tools := setupTools(artifactService)

	// Create the agent
	agent := agent.NewAgent(
		"rag-agent",
		googleModel,
		getSystemPrompt(),
		"A retrieval-augmented generation agent for answering questions about documents",
		tools,
	)

	// Start the conversation
	runInteractiveSession(ctx, agent)
}

func getSystemPrompt() string {
	return `You are a retrieval-augmented generation (RAG) agent designed to answer 
	questions about documents stored in a knowledge base.

	When a user asks a question, you should:
	1. Search the document repository for relevant information using the search_documents tool
	2. Retrieve the full content of relevant documents using the get_document tool
	3. Use the information from these documents to provide accurate answers
	4. Always cite your sources by mentioning which documents you used
	5. If the information is not available in the documents, politely state that you don't have that information

	You also have the ability to upload new documents to the repository using the upload_document tool.
	This allows users to add new information that you can reference in future queries.

	Always be helpful, accurate, and base your responses on the information in the documents.`
}

func setupTools(artifactService artifacts.ArtifactService) []tool.Tool {
	// Create a registry for the tools
	registry := tool.NewToolRegistry()

	// Tool to search documents by keywords
	searchTool := tool.NewBaseTool(
		"search_documents",
		"Search for documents that contain specific keywords",
		model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{
					"type":        "string",
					"description": "Keywords to search for in the documents",
				},
			},
			"required": []string{"query"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				Query string `json:"query"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse search params: %w", err)
			}

			// Search for documents (simulated for this example)
			results, err := searchDocuments(ctx, artifactService, params.Query)
			if err != nil {
				return "", fmt.Errorf("failed to search documents: %w", err)
			}

			// Format the results
			resultsJSON, err := sonic.MarshalIndent(results, "", "  ")
			if err != nil {
				return "", fmt.Errorf("failed to marshal search results: %w", err)
			}

			return string(resultsJSON), nil
		},
	)

	// Tool to get a document by ID
	getDocumentTool := tool.NewBaseTool(
		"get_document",
		"Retrieve a document by its ID",
		model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"id": map[string]any{
					"type":        "string",
					"description": "The ID of the document to retrieve",
				},
			},
			"required": []string{"id"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse document retrieval params: %w", err)
			}

			// Retrieve the document content
			docContent, err := getDocumentByID(ctx, artifactService, params.ID)
			if err != nil {
				return "", fmt.Errorf("failed to retrieve document: %w", err)
			}

			return docContent, nil
		},
	)

	// Tool to upload a new document
	uploadDocumentTool := tool.NewBaseTool(
		"upload_document",
		"Upload a new document to the repository",
		model.ToolParameterSpec{
			"type": "object",
			"properties": map[string]any{
				"title": map[string]any{
					"type":        "string",
					"description": "Title of the document",
				},
				"content": map[string]any{
					"type":        "string",
					"description": "Content of the document",
				},
				"metadata": map[string]any{
					"type":        "string",
					"description": "Optional metadata as JSON string",
				},
			},
			"required": []string{"title", "content"},
		},
		func(ctx context.Context, args json.RawMessage) (string, error) {
			// Parse the arguments
			var params struct {
				Title    string `json:"title"`
				Content  string `json:"content"`
				Metadata string `json:"metadata,omitempty"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", fmt.Errorf("failed to parse document upload params: %w", err)
			}

			// Process metadata if provided
			var metadata map[string]string
			if params.Metadata != "" {
				if err := sonic.Unmarshal([]byte(params.Metadata), &metadata); err != nil {
					return "", fmt.Errorf("failed to parse metadata: %w", err)
				}
			} else {
				metadata = make(map[string]string)
			}

			// Upload the document
			docID, err := uploadDocument(ctx, artifactService, params.Title, params.Content, metadata)
			if err != nil {
				return "", fmt.Errorf("failed to upload document: %w", err)
			}

			return fmt.Sprintf("Document uploaded successfully with ID: %s", docID), nil
		},
	)

	// Register the tools
	registry.Register(searchTool)
	registry.Register(getDocumentTool)
	registry.Register(uploadDocumentTool)

	return registry.GetAll()
}

// Document represents a document in the repository
type Document struct {
	ID       string            `json:"id"`
	Title    string            `json:"title"`
	Content  string            `json:"content"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SearchResult represents a document search result
type SearchResult struct {
	ID             string  `json:"id"`
	Title          string  `json:"title"`
	Snippet        string  `json:"snippet,omitempty"`
	RelevanceScore float64 `json:"relevance_score"`
}

// Functions to interact with the document store
func initializeDocumentStore(ctx context.Context, service artifacts.ArtifactService) {
	// Sample documents
	documents := []Document{
		{
			ID:      "doc1",
			Title:   "Introduction to Artificial Intelligence",
			Content: "Artificial Intelligence (AI) is the simulation of human intelligence processes by machines, especially computer systems. These processes include learning (the acquisition of information and rules for using the information), reasoning (using rules to reach approximate or definite conclusions), and self-correction. Particular applications of AI include expert systems, speech recognition, and machine vision.\n\nThe field of AI research was founded at a workshop held on the campus of Dartmouth College in the summer of 1956. The attendees, including John McCarthy, Marvin Minsky, Allen Newell, and Herbert Simon, became the leaders of AI research for many decades. They and their students wrote programs that were, to most people, simply astonishing: computers were solving word problems in algebra, proving logical theorems, and speaking English.\n\nBy the 1980s, AI research was in full swing, with many practical applications emerging in various fields. However, the field faced challenges in the form of what became known as the 'AI winter,' a period of reduced funding and interest in AI research. Despite these challenges, AI has continued to evolve and is now a critical component of many technologies we use daily.",
			Metadata: map[string]string{
				"author":   "John Smith",
				"year":     "2023",
				"category": "Technology",
				"keywords": "AI, Artificial Intelligence, Machine Learning, Deep Learning",
			},
		},
		{
			ID:      "doc2",
			Title:   "Machine Learning Fundamentals",
			Content: "Machine Learning (ML) is a subset of artificial intelligence that provides systems the ability to automatically learn and improve from experience without being explicitly programmed. It focuses on the development of computer programs that can access data and use it to learn for themselves.\n\nThe learning process begins with observations or data, such as examples, direct experience, or instruction, in order to look for patterns in data and make better decisions in the future based on the examples that we provide. The primary aim is to allow the computers to learn automatically without human intervention or assistance and adjust actions accordingly.\n\nMachine learning algorithms are often categorized as supervised, unsupervised, or reinforcement learning:\n\n1. Supervised learning: The algorithm is provided with a labeled dataset, which means some data has already been tagged with the correct answer. It involves learning a function that maps an input to an output based on example input-output pairs.\n\n2. Unsupervised learning: The algorithm is given data without explicit instructions on what to do with it. It involves finding patterns or structures in the input data without labeled outputs.\n\n3. Reinforcement learning: The algorithm learns by interacting with an environment and receiving rewards or penalties for actions taken. It involves learning how to act in order to maximize a reward signal.\n\nCommon machine learning algorithms include linear regression, logistic regression, decision trees, random forests, support vector machines, naive Bayes, k-nearest neighbors, k-means clustering, and neural networks (including deep learning architectures).",
			Metadata: map[string]string{
				"author":   "Jane Doe",
				"year":     "2022",
				"category": "Technology",
				"keywords": "Machine Learning, Algorithms, Supervised Learning, Unsupervised Learning",
			},
		},
		{
			ID:      "doc3",
			Title:   "Natural Language Processing Overview",
			Content: "Natural Language Processing (NLP) is a field of artificial intelligence that gives computers the ability to understand, interpret, and manipulate human language. NLP draws from many disciplines, including computer science and computational linguistics, to fill the gap between human communication and computer understanding.\n\nThe goal of NLP is to enable computers to process and analyze large amounts of natural language data. This involves tasks such as:\n\n1. Text classification: Categorizing text into predefined categories, such as spam detection or sentiment analysis.\n\n2. Text extraction: Identifying and extracting specific information from text, such as named entities or key phrases.\n\n3. Machine translation: Automatically translating text from one language to another.\n\n4. Text generation: Creating coherent and contextually relevant text, such as summaries or responses in a conversation.\n\n5. Speech recognition: Converting spoken language into written text.\n\nModern NLP approaches often use machine learning, particularly deep learning models like recurrent neural networks (RNNs), long short-term memory networks (LSTMs), and transformers. These models learn patterns and relationships in language from large datasets.\n\nTransformer models, such as BERT (Bidirectional Encoder Representations from Transformers) and GPT (Generative Pre-trained Transformer), have revolutionized NLP by enabling more effective learning of language context and semantics. These models have achieved state-of-the-art results on a wide range of NLP tasks.\n\nApplications of NLP include virtual assistants, chatbots, translation services, sentiment analysis tools, and content recommendation systems. As NLP continues to advance, we can expect more sophisticated and human-like language processing capabilities in our technology.",
			Metadata: map[string]string{
				"author":   "Michael Johnson",
				"year":     "2021",
				"category": "Technology",
				"keywords": "NLP, Natural Language Processing, Text Analysis, BERT, GPT",
			},
		},
	}

	// Store each document
	for _, doc := range documents {
		data, err := sonic.Marshal(doc)
		if err != nil {
			fmt.Printf("Error marshaling document: %v\n", err)
			continue
		}

		path := filepath.Join("documents", doc.ID)
		if err := service.StoreArtifact(ctx, path, data); err != nil {
			fmt.Printf("Error storing document: %v\n", err)
		}
	}
}

func searchDocuments(ctx context.Context, service artifacts.ArtifactService, query string) ([]SearchResult, error) {
	// List all documents
	docPaths, err := service.ListArtifacts(ctx, "documents")
	if err != nil {
		return nil, fmt.Errorf("failed to list documents: %w", err)
	}

	// Process each document for relevance
	var results []SearchResult
	for _, path := range docPaths {
		// Skip non-document files
		if !strings.HasPrefix(filepath.Base(path), "doc") {
			continue
		}

		// Load the document
		data, err := service.GetArtifact(ctx, path)
		if err != nil {
			fmt.Printf("Error loading document %s: %v\n", path, err)
			continue
		}

		var doc Document
		if err := sonic.Unmarshal(data, &doc); err != nil {
			fmt.Printf("Error unmarshaling document %s: %v\n", path, err)
			continue
		}

		// Simple relevance check - in a real app, use a proper search algorithm
		query = strings.ToLower(query)
		title := strings.ToLower(doc.Title)
		content := strings.ToLower(doc.Content)
		keywords := strings.ToLower(doc.Metadata["keywords"])

		// Count occurrences for a naive relevance score
		titleMatches := strings.Count(title, query)
		contentMatches := strings.Count(content, query)
		keywordMatches := strings.Count(keywords, query)

		// Calculate a simple relevance score
		relevance := float64(titleMatches*3 + contentMatches + keywordMatches*2)

		// If relevant, add to results
		if relevance > 0 || strings.Contains(title, query) || strings.Contains(content, query) || strings.Contains(keywords, query) {
			// Extract a snippet around the query
			snippet := extractSnippet(content, query)

			results = append(results, SearchResult{
				ID:             doc.ID,
				Title:          doc.Title,
				Snippet:        snippet,
				RelevanceScore: relevance,
			})
		}
	}

	// If no results found, return empty array
	if len(results) == 0 {
		return []SearchResult{}, nil
	}

	return results, nil
}

func extractSnippet(content, query string) string {
	content = strings.ToLower(content)
	query = strings.ToLower(query)

	// Find first occurrence of the query
	index := strings.Index(content, query)
	if index == -1 {
		// If not found, just return the first 100 chars
		if len(content) > 100 {
			return content[:100] + "..."
		}
		return content
	}

	// Extract a snippet around the query
	start := index - 50
	if start < 0 {
		start = 0
	}

	end := index + len(query) + 50
	if end > len(content) {
		end = len(content)
	}

	snippet := content[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(content) {
		snippet = snippet + "..."
	}

	return snippet
}

func getDocumentByID(ctx context.Context, service artifacts.ArtifactService, id string) (string, error) {
	// Load the document
	path := filepath.Join("documents", id)
	data, err := service.GetArtifact(ctx, path)
	if err != nil {
		return "", fmt.Errorf("document not found: %w", err)
	}

	var doc Document
	if err := sonic.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("error parsing document: %w", err)
	}

	// Format the document for display
	var formattedDoc strings.Builder

	formattedDoc.WriteString(fmt.Sprintf("# %s\n\n", doc.Title))
	formattedDoc.WriteString(doc.Content)
	formattedDoc.WriteString("\n\n")

	if len(doc.Metadata) > 0 {
		formattedDoc.WriteString("## Metadata\n\n")
		for key, value := range doc.Metadata {
			formattedDoc.WriteString(fmt.Sprintf("- %s: %s\n", key, value))
		}
	}

	return formattedDoc.String(), nil
}

func uploadDocument(ctx context.Context, service artifacts.ArtifactService, title, content string, metadata map[string]string) (string, error) {
	// List existing documents to get a new ID
	docPaths, err := service.ListArtifacts(ctx, "documents")
	if err != nil {
		return "", fmt.Errorf("failed to list documents: %w", err)
	}

	// Find the next available document ID
	highestID := 0
	for _, path := range docPaths {
		baseName := filepath.Base(path)
		if !strings.HasPrefix(baseName, "doc") {
			continue
		}

		idStr := strings.TrimPrefix(baseName, "doc")
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); err == nil {
			if id > highestID {
				highestID = id
			}
		}
	}

	// Create a new document ID
	newID := fmt.Sprintf("doc%d", highestID+1)

	// Create the document
	doc := Document{
		ID:       newID,
		Title:    title,
		Content:  content,
		Metadata: metadata,
	}

	// Serialize the document
	data, err := sonic.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("failed to marshal document: %w", err)
	}

	// Store the document
	path := filepath.Join("documents", newID)
	if err := service.StoreArtifact(ctx, path, data); err != nil {
		return "", fmt.Errorf("failed to store document: %w", err)
	}

	return newID, nil
}

func runInteractiveSession(ctx context.Context, agent *agent.Agent) {
	// Print welcome message
	fmt.Println("=== Retrieval-Augmented Generation (RAG) Agent ===")
	fmt.Println("Type 'exit' or 'quit' to end the conversation")
	fmt.Println("You can ask questions about the documents or upload new documents.")

	// Initialize scanner for user input
	scanner := bufio.NewScanner(os.Stdin)

	// Start the conversation history with a system message
	history := []message.Message{
		message.NewSystemMessage(getSystemPrompt()),
	}

	// Main conversation loop
	for {
		fmt.Print("\nYou: ")
		if !scanner.Scan() {
			break
		}
		userInput := scanner.Text()

		// Check for exit command
		if strings.EqualFold(userInput, "exit") || strings.EqualFold(userInput, "quit") {
			fmt.Println("\nThank you for using the RAG Agent. Goodbye!")
			break
		}

		// Add user message to history
		userMsg := message.NewUserMessage(userInput)
		history = append(history, userMsg)

		// Create a context with trace information
		ctxWithSpan, span := observability.StartSpan(ctx, "process_user_input")
		span.SetAttributes(attribute.String("user_input", userInput))
		defer span.End()

		// Process the message
		resp, err := agent.Process(ctxWithSpan, userMsg)
		if err != nil {
			fmt.Printf("\nError: %v\n", err)
			continue
		}

		// Add response to history
		history = append(history, resp)

		// Display the response
		fmt.Printf("\nAgent: %s\n", resp.Content)
	}
}
