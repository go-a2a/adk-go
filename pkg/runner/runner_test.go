// Copyright 2025 The ADK Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/go-a2a/adk-go/pkg/agent"
	"github.com/go-a2a/adk-go/pkg/artifacts"
	"github.com/go-a2a/adk-go/pkg/event"
	"github.com/go-a2a/adk-go/pkg/memory"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/runner"
	"github.com/go-a2a/adk-go/pkg/session"
)

// mockModel implements model.Model interface for testing
type mockModel struct{}

func (m *mockModel) Generate(ctx context.Context, messages []message.Message) (message.Message, error) {
	return message.NewAssistantMessage("mock response"), nil
}

func (m *mockModel) GenerateWithOptions(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	return message.NewAssistantMessage("mock response with options"), nil
}

func (m *mockModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	return message.NewAssistantMessage("mock response with tools"), nil
}

func (m *mockModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	return nil
}

func (m *mockModel) ModelID() string {
	return "mock-model"
}

func (m *mockModel) Provider() model.ModelProvider {
	return model.ModelProviderMock
}

func (m *mockModel) HasCapability(capability model.ModelCapability) bool {
	return true
}

// mockSessionService implements session.SessionService for testing
type mockSessionService struct {
	sessions map[string]map[string]map[string]*session.Session
	events   map[string][]event.Event
}

func newMockSessionService() *mockSessionService {
	return &mockSessionService{
		sessions: make(map[string]map[string]map[string]*session.Session),
		events:   make(map[string][]event.Event),
	}
}

func (m *mockSessionService) CreateSession(ctx context.Context, appName, userID, sessionID string) (*session.Session, error) {
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	
	// Initialize maps if they don't exist
	if _, ok := m.sessions[appName]; !ok {
		m.sessions[appName] = make(map[string]map[string]*session.Session)
	}
	if _, ok := m.sessions[appName][userID]; !ok {
		m.sessions[appName][userID] = make(map[string]*session.Session)
	}
	
	// Create session
	sess := session.NewSession(sessionID, appName, userID)
	m.sessions[appName][userID][sessionID] = sess
	m.events[sessionID] = []event.Event{}
	
	return sess, nil
}

func (m *mockSessionService) GetSession(ctx context.Context, appName, userID, sessionID string, maxEvents int, since *time.Time) (*session.Session, error) {
	if _, ok := m.sessions[appName]; !ok {
		return nil, nil
	}
	if _, ok := m.sessions[appName][userID]; !ok {
		return nil, nil
	}
	sess, ok := m.sessions[appName][userID][sessionID]
	if !ok {
		return nil, nil
	}
	return sess, nil
}

func (m *mockSessionService) ListSessions(ctx context.Context, appName, userID string) ([]*session.Session, error) {
	result := []*session.Session{}
	if _, ok := m.sessions[appName]; !ok {
		return result, nil
	}
	if _, ok := m.sessions[appName][userID]; !ok {
		return result, nil
	}
	for _, sess := range m.sessions[appName][userID] {
		result = append(result, sess)
	}
	return result, nil
}

func (m *mockSessionService) DeleteSession(ctx context.Context, appName, userID, sessionID string) error {
	if _, ok := m.sessions[appName]; !ok {
		return nil
	}
	if _, ok := m.sessions[appName][userID]; !ok {
		return nil
	}
	delete(m.sessions[appName][userID], sessionID)
	delete(m.events, sessionID)
	return nil
}

func (m *mockSessionService) CloseSession(ctx context.Context, appName, userID, sessionID string) error {
	return nil
}

func (m *mockSessionService) AppendEvent(ctx context.Context, appName, userID, sessionID string, e event.Event) error {
	if _, ok := m.events[sessionID]; !ok {
		m.events[sessionID] = []event.Event{}
	}
	m.events[sessionID] = append(m.events[sessionID], e)
	return nil
}

func (m *mockSessionService) ListEvents(ctx context.Context, appName, userID, sessionID string, maxEvents int, since *time.Time) ([]event.Event, error) {
	events, ok := m.events[sessionID]
	if !ok {
		return []event.Event{}, nil
	}
	
	if maxEvents > 0 && maxEvents < len(events) {
		return events[len(events)-maxEvents:], nil
	}
	return events, nil
}

// mockArtifactService implements artifacts.ArtifactService for testing
type mockArtifactService struct {
	artifacts map[string]map[string][]byte
}

func newMockArtifactService() *mockArtifactService {
	return &mockArtifactService{
		artifacts: make(map[string]map[string][]byte),
	}
}

func (m *mockArtifactService) SaveArtifact(ctx context.Context, sessionID, artifactID string, data []byte, mimeType string) error {
	if _, ok := m.artifacts[sessionID]; !ok {
		m.artifacts[sessionID] = make(map[string][]byte)
	}
	m.artifacts[sessionID][artifactID] = data
	return nil
}

func (m *mockArtifactService) GetArtifact(ctx context.Context, sessionID, artifactID string) ([]byte, string, error) {
	if _, ok := m.artifacts[sessionID]; !ok {
		return nil, "", nil
	}
	data, ok := m.artifacts[sessionID][artifactID]
	if !ok {
		return nil, "", nil
	}
	return data, "application/octet-stream", nil
}

func (m *mockArtifactService) ListArtifacts(ctx context.Context, sessionID string) ([]string, error) {
	if _, ok := m.artifacts[sessionID]; !ok {
		return []string{}, nil
	}
	result := []string{}
	for id := range m.artifacts[sessionID] {
		result = append(result, id)
	}
	return result, nil
}

func setupRunner() (*runner.Runner, *mockSessionService, *mockArtifactService) {
	// Create a model
	model := &mockModel{}
	
	// Create an agent
	agentInstance := agent.NewAgent("test-agent", model, "test instructions", "test description", nil)
	
	// Create services
	sessionSvc := newMockSessionService()
	artifactSvc := newMockArtifactService()
	memorySvc := memory.NewInMemoryService()
	
	// Create runner
	r := runner.NewRunner(agentInstance, runner.RunnerConfig{
		AppName:         "test-app",
		SessionService:  sessionSvc,
		ArtifactService: artifactSvc,
		MemoryService:   memorySvc,
	})
	
	return r, sessionSvc, artifactSvc
}

func TestNewRunner(t *testing.T) {
	// Create a model
	model := &mockModel{}
	
	// Create an agent
	agentInstance := agent.NewAgent("test-agent", model, "test instructions", "test description", nil)
	
	// Create a runner
	r := runner.NewRunner(agentInstance, runner.RunnerConfig{
		AppName: "test-app",
	})
	
	if r == nil {
		t.Fatalf("r is nil, want non-nil")
	}
}

func TestNewInMemoryRunner(t *testing.T) {
	// Create a model
	model := &mockModel{}
	
	// Create an agent
	agentInstance := agent.NewAgent("test-agent", model, "test instructions", "test description", nil)
	
	// Create an in-memory runner
	r := runner.NewInMemoryRunner("test-app", agentInstance)
	
	if r == nil {
		t.Fatalf("r is nil, want non-nil")
	}
}

func TestRunner_Run(t *testing.T) {
	r, sessionSvc, _ := setupRunner()
	
	// Test with a simple message
	response, err := r.Run(context.Background(), "Hello, world!")
	
	// Verify response
	if err != nil {
		t.Errorf("Run returned error: %v", err)
	}
	
	expectedResponse := "mock response"
	if response.Content != expectedResponse {
		t.Errorf("Response content = %q, want %q", response.Content, expectedResponse)
	}
	
	// Check that a session was created
	sessions, err := sessionSvc.ListSessions(context.Background(), "test-app", "")
	if err != nil {
		t.Errorf("ListSessions returned error: %v", err)
	}
	
	// Should have at least one session for some user
	foundSession := false
	for userID, userSessions := range sessionSvc.sessions["test-app"] {
		if len(userSessions) > 0 {
			foundSession = true
			break
		}
	}
	
	if !foundSession {
		t.Errorf("No sessions were created")
	}
}

func TestRunner_RunConversation(t *testing.T) {
	r, sessionSvc, _ := setupRunner()
	
	userID := "test-user"
	messages := []message.Message{
		message.NewUserMessage("Hello"),
		message.NewAssistantMessage("Hi there"),
		message.NewUserMessage("How are you?"),
	}
	
	// Run the conversation
	response, err := r.RunConversation(context.Background(), userID, messages)
	
	// Verify response
	if err != nil {
		t.Errorf("RunConversation returned error: %v", err)
	}
	
	expectedResponse := "mock response"
	if response.Content != expectedResponse {
		t.Errorf("Response content = %q, want %q", response.Content, expectedResponse)
	}
	
	// Check that a session was created for the user
	sessions, err := sessionSvc.ListSessions(context.Background(), "test-app", userID)
	if err != nil {
		t.Errorf("ListSessions returned error: %v", err)
	}
	
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session for user, got %d", len(sessions))
	}
	
	// Check that events were created in the session
	if len(sessions) > 0 {
		sessionID := sessions[0].ID
		events, err := sessionSvc.ListEvents(context.Background(), "test-app", userID, sessionID, 0, nil)
		if err != nil {
			t.Errorf("ListEvents returned error: %v", err)
		}
		
		// Should have 2 events - the last user message and the assistant response
		if len(events) != 2 {
			t.Errorf("Expected 2 events, got %d", len(events))
		}
	}
}

func TestRunner_RunWithSession(t *testing.T) {
	r, sessionSvc, _ := setupRunner()
	
	userID := "test-user"
	
	// Create a session first
	session, err := sessionSvc.CreateSession(context.Background(), "test-app", userID, "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sessionID := session.ID
	
	// Run with the existing session
	message := message.NewUserMessage("Hello with session")
	response, err := r.RunWithSession(context.Background(), userID, sessionID, []message.Message{message})
	
	// Verify response
	if err != nil {
		t.Errorf("RunWithSession returned error: %v", err)
	}
	
	expectedResponse := "mock response"
	if response.Content != expectedResponse {
		t.Errorf("Response content = %q, want %q", response.Content, expectedResponse)
	}
	
	// Check that events were created in the session
	events, err := sessionSvc.ListEvents(context.Background(), "test-app", userID, sessionID, 0, nil)
	if err != nil {
		t.Errorf("ListEvents returned error: %v", err)
	}
	
	// Should have 2 events - the user message and the assistant response
	if len(events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(events))
	}
}

func TestRunner_RunAsync(t *testing.T) {
	r, _, _ := setupRunner()
	
	userID := "test-user"
	message := message.NewUserMessage("Hello async")
	
	// Run asynchronously
	responseCh, errCh := r.RunAsync(context.Background(), userID, "", message)
	
	// Get the response
	var response message.Message
	var runErr error
	
	select {
	case resp := <-responseCh:
		response = resp
	case err := <-errCh:
		runErr = err
	case <-time.After(2 * time.Second): // Add timeout
		t.Fatal("Timeout waiting for response")
	}
	
	// Check for errors
	if runErr != nil {
		t.Errorf("RunAsync returned error: %v", runErr)
	}
	
	// Verify response
	expectedResponse := "mock response"
	if response.Content != expectedResponse {
		t.Errorf("Response content = %q, want %q", response.Content, expectedResponse)
	}
}

func TestRunner_RunWithSession_EmptyMessages(t *testing.T) {
	r, _, _ := setupRunner()
	
	userID := "test-user"
	
	// Run with empty messages
	response, err := r.RunWithSession(context.Background(), userID, "", []message.Message{})
	
	// Should not error, but return empty message
	if err != nil {
		t.Errorf("RunWithSession with empty messages returned error: %v", err)
	}
	
	emptyMessage := message.Message{}
	if !cmp.Equal(response, emptyMessage) {
		t.Errorf("Expected empty message, got %+v", response)
	}
}

func TestRunner_RunWithArtifacts(t *testing.T) {
	r, _, artifactSvc := setupRunner()
	
	userID := "test-user"
	
	// Create a message with an artifact
	artifact := message.Artifact{
		MimeType: "text/plain",
		Data:     []byte("artifact data"),
	}
	
	msg := message.NewUserMessage("Message with artifact")
	msg.Artifacts = []message.Artifact{artifact}
	
	// Run with the artifact
	response, err := r.RunWithSession(context.Background(), userID, "", []message.Message{msg})
	
	// Verify response
	if err != nil {
		t.Errorf("RunWithSession returned error: %v", err)
	}
	
	// Check that the artifact was saved
	found := false
	for sessionID, sessionArtifacts := range artifactSvc.artifacts {
		if len(sessionArtifacts) > 0 {
			found = true
			break
		}
	}
	
	if !found {
		t.Errorf("No artifacts were saved")
	}
}