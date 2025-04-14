// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package session provides facilities for managing user sessions
// with AI agents.
//
// The package includes:
//
// * Session: Represents a series of interactions between a user and agents.
//
// * State: Provides a flexible, dictionary-like state management system with change tracking.
//
// * SessionService: Interface for storing and retrieving sessions.
//
// * InMemorySessionService: Implementation of SessionService that stores sessions in memory.
//
// Session state is managed with prefix conventions:
//
// * app: - App-level state shared across all users
// * user: - User-level state shared across all sessions for a user
// * temp: - Temporary state that exists only within the current session
//
// Example:
//
//	// Create a session service
//	service := session.NewInMemorySessionService()
//
//	// Create a new session
//	s, err := service.CreateSession(ctx, "my-app", "user123", "")
//	if err != nil {
//		log.Fatalf("Failed to create session: %v", err)
//	}
//
//	// Add an event with state changes
//	e := MyEvent{
//		// Event implementation that updates state with "app:mykey" -> "value"
//	}
//	err = service.AppendEvent(ctx, "my-app", "user123", s.ID, e)
package session
