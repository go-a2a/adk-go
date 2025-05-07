// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"context"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// Planner defines the interface for planning strategies.
type Planner interface {
	// BuildPlanningInstruction generates a system instruction for planning.
	// This instruction will be appended to the LLM request.
	BuildPlanningInstruction(ctx context.Context, rctx *types.ReadOnlyContext, request *types.LLMRequest) (string, error)

	// ProcessPlanningResponse processes the LLM response for planning.
	// It can modify, filter, or structure the response parts.
	ProcessPlanningResponse(ctx context.Context, cctx *types.CallbackContext, responseParts []*genai.Part) ([]*genai.Part, error)
}
