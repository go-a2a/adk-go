// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/go-a2a/adk-go/pkg/event"
)

// Entity represents a node in the knowledge graph.
type Entity struct {
	// Type is the type of the entity (always "entity").
	Type string `json:"type"`
	
	// Name is the unique identifier for the entity.
	Name string `json:"name"`
	
	// EntityType is the category of entity.
	EntityType string `json:"entityType"`
	
	// Observations are the properties or attributes of the entity.
	Observations []string `json:"observations"`
}

// Relation represents an edge in the knowledge graph.
type Relation struct {
	// Type is the type of the relation (always "relation").
	Type string `json:"type"`
	
	// From is the source entity name.
	From string `json:"from"`
	
	// To is the target entity name.
	To string `json:"to"`
	
	// RelationType is the type of relationship.
	RelationType string `json:"relationType"`
}

// GraphNode represents either an Entity or a Relation.
type GraphNode struct {
	// Type is either "entity" or "relation".
	Type string `json:"type"`
	
	// Raw contains the original JSON data.
	Raw json.RawMessage `json:"-"`
	
	// Entity holds the entity data if Type is "entity".
	Entity *Entity `json:"-"`
	
	// Relation holds the relation data if Type is "relation".
	Relation *Relation `json:"-"`
}

// KnowledgeGraph represents a collection of entities and relations.
type KnowledgeGraph struct {
	// Entities maps entity names to Entity objects.
	Entities map[string]*Entity
	
	// Relations is a slice of all relations.
	Relations []*Relation
}

// KnowledgeGraphMemoryService is a memory service based on a knowledge graph.
type KnowledgeGraphMemoryService struct {
	// mu protects the graph.
	mu sync.RWMutex
	
	// graph is the knowledge graph.
	graph *KnowledgeGraph
	
	// sessionToEntities maps session IDs to entity names.
	sessionToEntities map[string][]string
}

// NewKnowledgeGraphMemoryService creates a new KnowledgeGraphMemoryService.
func NewKnowledgeGraphMemoryService() *KnowledgeGraphMemoryService {
	return &KnowledgeGraphMemoryService{
		graph: &KnowledgeGraph{
			Entities:  make(map[string]*Entity),
			Relations: []*Relation{},
		},
		sessionToEntities: make(map[string][]string),
	}
}

// LoadFromFile loads a knowledge graph from a JSON file.
func (s *KnowledgeGraphMemoryService) LoadFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open knowledge graph file: %w", err)
	}
	defer file.Close()
	
	return s.LoadFromReader(file)
}

// LoadFromReader loads a knowledge graph from a JSON reader.
func (s *KnowledgeGraphMemoryService) LoadFromReader(reader io.Reader) error {
	// Read the entire file
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read knowledge graph data: %w", err)
	}
	
	// Split the JSON data into lines (each line is a complete JSON object)
	lines := strings.Split(string(data), "\n")
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Process each line
	for _, line := range lines {
		// Skip empty lines
		if line == "" {
			continue
		}
		
		// Parse the JSON node
		var node GraphNode
		if err := json.Unmarshal([]byte(line), &node); err != nil {
			return fmt.Errorf("failed to parse JSON node: %w", err)
		}
		
		// Store the raw JSON
		node.Raw = json.RawMessage(line)
		
		// Process based on node type
		switch node.Type {
		case "entity":
			var entity Entity
			if err := json.Unmarshal([]byte(line), &entity); err != nil {
				return fmt.Errorf("failed to parse entity: %w", err)
			}
			node.Entity = &entity
			s.graph.Entities[entity.Name] = &entity
			
		case "relation":
			var relation Relation
			if err := json.Unmarshal([]byte(line), &relation); err != nil {
				return fmt.Errorf("failed to parse relation: %w", err)
			}
			node.Relation = &relation
			s.graph.Relations = append(s.graph.Relations, &relation)
			
		default:
			return fmt.Errorf("unknown node type: %s", node.Type)
		}
	}
	
	return nil
}

// AddSessionToMemory adds a session to the memory service.
func (s *KnowledgeGraphMemoryService) AddSessionToMemory(ctx context.Context, session *Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	// Create entity name for the session
	entityName := fmt.Sprintf("Session_%s", session.ID)
	
	// Create observations from event content
	var observations []string
	for _, evt := range session.Events {
		if evt != nil && evt.Content != "" {
			observations = append(observations, evt.Content)
		}
	}
	
	// Skip if no observations
	if len(observations) == 0 {
		return nil
	}
	
	// Create entity
	entity := &Entity{
		Type:         "entity",
		Name:         entityName,
		EntityType:   "Session",
		Observations: observations,
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Add entity to graph
	s.graph.Entities[entityName] = entity
	
	// Associate with session
	s.sessionToEntities[session.ID] = append(s.sessionToEntities[session.ID], entityName)
	
	return nil
}

// SearchMemory searches for sessions that match the query.
func (s *KnowledgeGraphMemoryService) SearchMemory(ctx context.Context, appName string, userID string, query string) (*SearchMemoryResponse, error) {
	if query == "" {
		return nil, fmt.Errorf("query cannot be empty")
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	// Prepare response
	response := &SearchMemoryResponse{
		Memories: []*MemoryResult{},
	}
	
	// Create map to track matched sessions
	matchedSessions := make(map[string][]*event.Event)
	
	// Search entities for query terms
	for entityName, entity := range s.graph.Entities {
		// Skip if not a session entity
		if entity.EntityType != "Session" {
			continue
		}
		
		// Extract session ID from entity name
		sessionID := strings.TrimPrefix(entityName, "Session_")
		
		// Check observations for query terms
		var matchedEvents []*event.Event
		for _, obs := range entity.Observations {
			if strings.Contains(strings.ToLower(obs), strings.ToLower(query)) {
				// Create event from observation
				evt := &event.Event{
					InvocationID: fmt.Sprintf("kg_%d", len(matchedEvents)),
					Author:       "knowledge_graph",
					Content:      obs,
				}
				matchedEvents = append(matchedEvents, evt)
			}
		}
		
		// Add to matched sessions if any matches
		if len(matchedEvents) > 0 {
			matchedSessions[sessionID] = matchedEvents
		}
	}
	
	// Build response from matched sessions
	for sessionID, events := range matchedSessions {
		response.Memories = append(response.Memories, &MemoryResult{
			SessionID: sessionID,
			Events:    events,
		})
	}
	
	return response, nil
}