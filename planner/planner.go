// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"context"

	"github.com/go-a2a/adk-go/agent"
	"github.com/go-a2a/adk-go/model"
)

// Planner defines the interface for planning strategies.
type Planner interface {
	// BuildPlanningInstruction generates a system instruction for planning.
	// This instruction will be appended to the LLM request.
	BuildPlanningInstruction(ctx context.Context, rctx *agent.ReadOnlyContext, request *model.LLMRequest) (string, error)

	// ProcessPlanningResponse processes the LLM response for planning.
	// It can modify, filter, or structure the response parts.
	ProcessPlanningResponse(ctx context.Context, cctx *agent.CallbackContext, responseParts []any) ([]any, error)
}
