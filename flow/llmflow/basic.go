// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"context"
	"iter"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// BasicLLMRequestProcessor is a simple implementation of LLMFlow that just passes content
// to the LLM and returns the response.
type BasicLLMRequestProcessor struct{}

var _ types.LLMRequestProcessor = (*BasicLLMRequestProcessor)(nil)

// Run implements [LLMRequestProcessor].
func (f *BasicLLMRequestProcessor) Run(ctx context.Context, ictx *types.InvocationContext, request *types.LLMRequest) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		llmAgent, ok := ictx.Agent.AsLLMAgent()
		if !ok {
			return
		}

		model, err := llmAgent.CanonicalModel(ctx)
		if err != nil {
			yield(nil, err)
			return
		}
		request.Model = model.Name()

		config := llmAgent.GenerateContentConfig()
		if config == nil {
			config = &genai.GenerateContentConfig{}
		}
		request.Config = config

		if outputschema := llmAgent.OutputSchema(); outputschema != nil {
			request.SetOutputSchema(outputschema)
		}

		request.LiveConnectConfig.ResponseModalities = ictx.RunConfig.ResponseModalities
		request.LiveConnectConfig.SpeechConfig = ictx.RunConfig.SpeechConfig
		request.LiveConnectConfig.OutputAudioTranscription = ictx.RunConfig.OutputAudioTranscription
		request.LiveConnectConfig.InputAudioTranscription = ictx.RunConfig.InputAudioTranscription

		// TODO(adk-python): handle tool append here, instead of in BaseTool.process_llm_request.

		return
	}
}
