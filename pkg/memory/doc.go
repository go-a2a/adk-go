// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

/*
Package memory provides storage and retrieval services for agent conversations and knowledge.

It defines interfaces and implementations for managing memory in AI agent systems, including:

  - MemoryService interface that defines core operations for adding sessions to memory
    and searching memory based on queries.

  - InMemoryMemoryService for simple, in-memory storage using keyword matching.
    This is primarily intended for prototyping and testing.

  - VectorMemoryService for simulated vector-based search and retrieval.
    This mimics how systems like Vertex AI RAG would work in production.

  - KnowledgeGraphMemoryService for storing and retrieving information from a
    knowledge graph, demonstrating a structured approach to memory with entities and relations.

Sessions are the core unit of memory storage, representing conversations between
users and agents. Each session contains events, which are individual user and agent messages.

Example usage:

	// Create an in-memory memory service
	memoryService := memory.NewInMemoryMemoryService()

	// Create a session
	session := &memory.Session{
		ID:        "session-123",
		AppName:   "my-app",
		UserID:    "user-abc",
		StartTime: time.Now(),
		Events: []*event.Event{
			{
				InvocationID: "inv-1",
				Author:       "user",
				Content:      "How do I create a goroutine in Go?",
			},
			{
				InvocationID: "inv-2",
				Author:       "assistant",
				Content:      "You can create a goroutine by using the go keyword followed by a function call.",
			},
		},
	}

	// Add the session to memory
	err := memoryService.AddSessionToMemory(context.Background(), session)
	if err != nil {
		log.Fatalf("Failed to add session: %v", err)
	}

	// Search memory
	response, err := memoryService.SearchMemory(context.Background(), "my-app", "user-abc", "goroutine")
	if err != nil {
		log.Fatalf("Failed to search memory: %v", err)
	}

	// Process search results
	for _, memory := range response.Memories {
		fmt.Printf("Session: %s\n", memory.SessionID)
		for _, evt := range memory.Events {
			fmt.Printf("  %s: %s\n", evt.Author, evt.Content)
		}
	}
*/
package memory
