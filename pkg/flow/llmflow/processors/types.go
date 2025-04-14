// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

// Package processors provides processor implementations for LLM flows.
package processors

import (
	"github.com/go-a2a/adk-go/pkg/flow"
)

// RequestProcessor provides a base implementation for LLM request processors.
type RequestProcessor struct {
	flow.BaseRequestProcessor
}

// NewRequestProcessor creates a new RequestProcessor with the given name.
func NewRequestProcessor(name string) *RequestProcessor {
	return &RequestProcessor{
		BaseRequestProcessor: *flow.NewBaseRequestProcessor(name),
	}
}

// ResponseProcessor provides a base implementation for LLM response processors.
type ResponseProcessor struct {
	flow.BaseResponseProcessor
}

// NewResponseProcessor creates a new ResponseProcessor with the given name.
func NewResponseProcessor(name string) *ResponseProcessor {
	return &ResponseProcessor{
		BaseResponseProcessor: *flow.NewBaseResponseProcessor(name),
	}
}
