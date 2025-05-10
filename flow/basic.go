// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"iter"

	"github.com/go-a2a/adk-go/agent"
	"github.com/go-a2a/adk-go/types"
)

// BasicLlmRequestProcessor is a simple implementation of LLMFlow that just passes content
// to the LLM and returns the response.
type BasicLlmRequestProcessor struct{}

var _ BaseLLMRequestProcessor = (*BasicLlmRequestProcessor)(nil)

func (f *BasicLlmRequestProcessor) Run(ctx context.Context, ic *types.InvocationContext, req *types.LLMRequest) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		a := ic.Agent
		llmAgent, ok := a.(*agent.LLMAgent)
		if !ok {
			return
		}

		var err error
		req.Model, err = llmAgent.CanonicalModel(ctx)
		if err != nil {
			yield(nil, err)
			return
		}
	}
}
