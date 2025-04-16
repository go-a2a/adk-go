// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"fmt"
	"strings"

	"github.com/go-a2a/adk-go/message"
)

const (
	// Planning tags used to structure model output
	PlanningTag       = "<planning>"
	PlanningEndTag    = "</planning>"
	ReasoningTag      = "<reasoning>"
	ReasoningEndTag   = "</reasoning>"
	ActionTag         = "<action>"
	ActionEndTag      = "</action>"
	FinalAnswerTag    = "<final_answer>"
	FinalAnswerEndTag = "</final_answer>"
)

// PlanReActPlanner implements a structured planner using Plan-Reasoning-Action-Thinking approach.
// It guides the model to create explicit plans, reason about execution, perform actions,
// and provide final answers.
type PlanReActPlanner struct {
	// enableFinalAnswerCheck determines if the planner should ensure final answers are provided.
	enableFinalAnswerCheck bool

	// requireStructuredOutput determines if the planner should enforce structured outputs.
	requireStructuredOutput bool
}

// PlanReActPlannerOption represents a configuration option for the PlanReActPlanner.
type PlanReActPlannerOption func(*PlanReActPlanner)

// WithFinalAnswerCheck configures whether to check for final answers.
func WithFinalAnswerCheck(enabled bool) PlanReActPlannerOption {
	return func(p *PlanReActPlanner) {
		p.enableFinalAnswerCheck = enabled
	}
}

// WithStructuredOutput configures whether to require structured outputs.
func WithStructuredOutput(required bool) PlanReActPlannerOption {
	return func(p *PlanReActPlanner) {
		p.requireStructuredOutput = required
	}
}

// NewPlanReActPlanner creates a new PlanReActPlanner with the given options.
func NewPlanReActPlanner(opts ...PlanReActPlannerOption) *PlanReActPlanner {
	planner := &PlanReActPlanner{
		enableFinalAnswerCheck:  true,
		requireStructuredOutput: true,
	}

	for _, opt := range opts {
		opt(planner)
	}

	return planner
}

// BuildPlanningInstruction implements the Planner interface.
// It generates a system instruction for the planning process.
func (p *PlanReActPlanner) BuildPlanningInstruction(ctx *Context, request *LlmRequest) (string, error) {
	return p.buildNLPlannerInstruction(), nil
}

// ProcessPlanningResponse implements the Planner interface.
// It processes the LLM response to ensure it follows the planning structure.
func (p *PlanReActPlanner) ProcessPlanningResponse(ctx *CallbackContext, responseParts []message.Message) ([]message.Message, error) {
	if len(responseParts) == 0 {
		return responseParts, nil
	}

	// Process non-function call parts
	result := make([]message.Message, 0, len(responseParts))
	for _, part := range responseParts {
		if len(part.ToolCalls) > 0 {
			// Function call parts are included as-is
			result = append(result, part)
		} else {
			// Process and structure non-function call parts
			processed, err := p.handleNonFunctionCallParts(part)
			if err != nil {
				return nil, err
			}
			result = append(result, processed)
		}
	}

	return result, nil
}

// handleNonFunctionCallParts processes text content to enforce planning structure.
func (p *PlanReActPlanner) handleNonFunctionCallParts(part message.Message) (message.Message, error) {
	if !p.requireStructuredOutput {
		return part, nil
	}

	content := part.Content

	// Ensure content is properly structured if required
	if p.enableFinalAnswerCheck && !strings.Contains(content, FinalAnswerTag) {
		// If there's no final answer, wrap the content in final answer tags
		if !strings.Contains(content, PlanningTag) &&
			!strings.Contains(content, ReasoningTag) &&
			!strings.Contains(content, ActionTag) {
			content = fmt.Sprintf("%s%s%s", FinalAnswerTag, content, FinalAnswerEndTag)
		}
	}

	result := part.Clone()
	result.Content = content
	return result, nil
}

// buildNLPlannerInstruction creates the natural language planning instruction.
//
// TODO(zchee): fix logic to same as adk-python.
func (p *PlanReActPlanner) buildNLPlannerInstruction() string {
	prompt := `To effectively solve the user's query, follow this systematic approach:

1. PLANNING PHASE
   ${PlanningTag}
   - Create a detailed plan covering all aspects of the query
   - Break complex problems into manageable steps
   - Consider edge cases and potential issues
   ${PlanningEndTag}

2. REASONING PHASE
   ${ReasoningTag}
   - Show your reasoning process for each step
   - Explain your approach and justify decisions
   - Consider alternatives and tradeoffs
   ${ReasoningEndTag}

3. ACTION PHASE
   ${ActionTag}
   - Execute your plan using available tools
   - Use code snippets as needed within actions
   - Test your solutions with examples
   ${ActionEndTag}

4. FINAL ANSWER
   ${FinalAnswerTag}
   - Provide a clear, concise, and complete answer
   - Focus on addressing exactly what was asked
   - Use proper formatting for readability
   ${FinalAnswerEndTag}

IMPORTANT GUIDELINES:
- Prioritize using tools over relying on memorized information
- Revise your plan if initial execution fails
- Ensure answers are specific and contextually appropriate
- Use the designated tags to structure your response
- Be thorough but concise in your explanations`
	prompt = strings.ReplaceAll(prompt, "${PlanningTag}", PlanningTag)
	prompt = strings.ReplaceAll(prompt, "${PlanningEndTag}", PlanningEndTag)
	prompt = strings.ReplaceAll(prompt, "${ReasoningTag}", ReasoningTag)
	prompt = strings.ReplaceAll(prompt, "${ReasoningEndTag}", ReasoningEndTag)
	prompt = strings.ReplaceAll(prompt, "${ActionTag}", ActionTag)
	prompt = strings.ReplaceAll(prompt, "${ActionEndTag}", ActionEndTag)
	prompt = strings.ReplaceAll(prompt, "${FinalAnswerTag}", FinalAnswerTag)
	prompt = strings.ReplaceAll(prompt, "${FinalAnswerEndTag}", FinalAnswerEndTag)

	return prompt
}
