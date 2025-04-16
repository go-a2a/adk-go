// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/artifact"
	"github.com/go-a2a/adk-go/memory"
	"github.com/go-a2a/adk-go/observability"
	"github.com/go-a2a/adk-go/session"
)

// InvocationContext contains contextual information for a single agent invocation.
type InvocationContext struct {
	artifactService      artifact.ArtifactService
	sessionService       session.SessionService
	memoryService        memory.MemoryService
	id                   string
	branch               string
	agent                *BaseAgent
	userContent          *genai.Content
	endInvocation        bool
	liveRequestOueue     *LiveRequestQueue
	activeStreamingTools map[string]*ActiveStreamingTool
	transcriptionCache   []*TranscriptionEntry
	RunConfig            *RunConfig

	appName   string
	userID    string
	sessionID string
	session   *session.Session
	logger    *slog.Logger
	startTime time.Time
}

// InvocationContextOption represents an option for configuring the [InvocationContext].
type InvocationContextOption interface {
	apply(*InvocationContext) *InvocationContext
}

type userIDOption string

var _ InvocationContextOption = (*userIDOption)(nil)

func (o userIDOption) apply(ictx *InvocationContext) *InvocationContext {
	ictx.userID = string(o)
	return ictx
}

func WithUserID(userID string) InvocationContextOption {
	return userIDOption(userID)
}

type sessionIDOption string

var _ InvocationContextOption = (*sessionIDOption)(nil)

func (o sessionIDOption) apply(ictx *InvocationContext) *InvocationContext {
	ictx.userID = string(o)
	return ictx
}

func WithSessionIDOption(userID string) InvocationContextOption {
	return sessionIDOption(userID)
}

type loggerOption struct {
	logger *slog.Logger
}

var _ InvocationContextOption = (*loggerOption)(nil)

func (o loggerOption) apply(ictx *InvocationContext) *InvocationContext {
	ictx.logger = o.logger
	return ictx
}

func WithLoggerOption(logger *slog.Logger) InvocationContextOption {
	return loggerOption{logger: logger}
}

type startTimeOption time.Time

var _ InvocationContextOption = (*startTimeOption)(nil)

func (o startTimeOption) apply(ictx *InvocationContext) *InvocationContext {
	ictx.startTime = time.Time(o)
	return ictx
}

func WithStartTimeOption(t time.Time) InvocationContextOption {
	return startTimeOption(t)
}

// NewInvocationContext creates a new InvocationContext.
func NewInvocationContext(ctx context.Context, appName string, sess *session.Session, opts ...InvocationContextOption) *InvocationContext {
	ictx := &InvocationContext{
		appName:         appName,
		session:         sess,
		artifactService: artifact.NewInMemoryArtifactService(),
		sessionService:  session.NewInMemorySessionService(),
		memoryService:   memory.NewInMemoryMemoryService(),
		logger:          observability.Logger(ctx),
	}

	for _, o := range opts {
		ictx = o.apply(ictx)
	}

	return ictx
}

// AppName returns the name of the application associated with this invocation context.
func (ictx *InvocationContext) AppName() string {
	return ictx.appName
}

// UserID returns the name of the application associated with this invocation context.
func (ictx *InvocationContext) UserID() string {
	return ictx.userID
}

// SessionID returns the session ID associated with this invocation context.
func (ictx *InvocationContext) SessionID() string {
	return ictx.userID
}

// Session returns the session associated with this invocation context.
func (ictx *InvocationContext) Session() *session.Session {
	return ictx.session
}

// ArtifactService returns the [artifact.ArtifactService] associated with this invocation context.
func (ictx *InvocationContext) ArtifactService() artifact.ArtifactService {
	return ictx.artifactService
}

// SessionService returns the [session.SessionService] associated with this invocation context.
func (ictx *InvocationContext) SessionService() session.SessionService {
	return ictx.sessionService
}

// MemoryService returns the [memory.MemoryService] associated with this invocation context.
func (ictx *InvocationContext) MemoryService() memory.MemoryService {
	return ictx.memoryService
}

// Logger returns the [slog.Logger] associated with this invocation context.
func (ictx *InvocationContext) Logger() *slog.Logger {
	return ictx.logger
}

// StartTime returns the [time.Time] associated with this invocation context.
func (ictx *InvocationContext) StartTime() time.Time {
	return ictx.startTime
}
