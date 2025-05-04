// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"google.golang.org/genai"
)

type StreamingMode string

const (
	StreamingModeNone StreamingMode = "None"
	StreamingModeSSE  StreamingMode = "sse"
	StreamingModeBIDI StreamingMode = "bidi"
)

// RunConfig configs for runtime behavior of agents.
type RunConfig struct {
	// SpeechConfig is the speech configuration for the live agent.
	SpeechConfig *genai.SpeechConfig

	// ResponseModalities is the output modalities. If not set, it's default to AUDIO.
	ResponseModalities []string

	// SaveInputBlobsAsArtifacts whether or not to save the input blobs as artifacts.
	SaveInputBlobsAsArtifacts bool

	// SupportCFC whether to support CFC (Compositional Function Calling). Only applicable for
	// [StreamingModeSSE]. If it's true. the LIVE API will be invoked. Since only LIVE
	// API supports CFC.
	//
	// Warning:
	// This feature is **experimental** and its API or behavior may change
	// in future releases.
	SupportCFC bool

	// Streaming mode, None or StreamingMode.SSE or StreamingMode.BIDI.
	StreamingMode StreamingMode

	// OutputAudioTranscription output transcription for live agents with audio response.
	OutputAudioTranscription *genai.AudioTranscriptionConfig

	// MaxLLMCalls a limit on the total number of llm calls for a given run.
	//
	// Valid Values:
	//   - More than 0 and less than sys.maxsize: The bound on the number of llm
	//     calls is enforced, if the value is set in this range.
	//   - Less than or equal to 0: This allows for unbounded number of llm calls.
	MaxLLMCalls int // 500
}

// TODO(zchee): implements
// func (rc *RunConfig) ValidateMaxLLMCalls(value int) int {}
