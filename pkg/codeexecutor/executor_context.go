// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package codeexecutor

import (
	"sync"
	"time"
)

// Constants for context keys.
const (
	ContextKey             = "context"
	InputFileKey           = "input_files"
	ErrorCountKey          = "error_count"
	CodeExecutionResultKey = "code_execution_results"
)

// SessionState tracks the overall state of a code execution session.
type SessionState struct {
	ExecutionID string
}

// CodeExecutorContext manages persistent context for code execution.
type CodeExecutorContext struct {
	mu            sync.RWMutex
	context       map[string]any
	sessionState  SessionState
	inputFiles    map[string][]byte
	errorCounts   map[string]int
	executionLogs []CodeExecutionResult
}

// NewCodeExecutorContext creates a new CodeExecutorContext.
func NewCodeExecutorContext() *CodeExecutorContext {
	return &CodeExecutorContext{
		context:       make(map[string]any),
		sessionState:  SessionState{},
		inputFiles:    make(map[string][]byte),
		errorCounts:   make(map[string]int),
		executionLogs: []CodeExecutionResult{},
	}
}

// GetInputFiles returns the list of input files.
func (c *CodeExecutorContext) GetInputFiles() map[string][]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string][]byte, len(c.inputFiles))
	for k, v := range c.inputFiles {
		result[k] = v
	}
	return result
}

// AddInputFiles adds new input files to the context.
func (c *CodeExecutorContext) AddInputFiles(files map[string][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range files {
		c.inputFiles[k] = v
	}
}

// ClearInputFiles removes all input files.
func (c *CodeExecutorContext) ClearInputFiles() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inputFiles = make(map[string][]byte)
}

// GetExecutionID returns the unique session identifier.
func (c *CodeExecutorContext) GetExecutionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionState.ExecutionID
}

// SetExecutionID sets the session identifier.
func (c *CodeExecutorContext) SetExecutionID(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionState.ExecutionID = id
}

// GetErrorCount gets the error count for an invocation.
func (c *CodeExecutorContext) GetErrorCount(invocationID string) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.errorCounts[invocationID]
}

// IncrementErrorCount increases the error count for an invocation.
func (c *CodeExecutorContext) IncrementErrorCount(invocationID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errorCounts[invocationID]++
	return c.errorCounts[invocationID]
}

// UpdateCodeExecutionResult logs execution details.
func (c *CodeExecutorContext) UpdateCodeExecutionResult(result CodeExecutionResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result.Timestamp = time.Now()
	c.executionLogs = append(c.executionLogs, result)
}

// GetCodeExecutionResults returns all execution results.
func (c *CodeExecutorContext) GetCodeExecutionResults() []CodeExecutionResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	results := make([]CodeExecutionResult, len(c.executionLogs))
	copy(results, c.executionLogs)
	return results
}
