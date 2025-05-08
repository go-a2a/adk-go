// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/go-a2a/adk-go/agent"
	"github.com/go-a2a/adk-go/types"
)

// AgentTransferLlmRequestProcessor represents an agent transfer request processor.
type AgentTransferLlmRequestProcessor struct{}

var _ BaseLLMRequestProcessor = (*AgentTransferLlmRequestProcessor)(nil)

// Run implements [BaseLLMRequestProcessor].
func (rp *AgentTransferLlmRequestProcessor) Run(ctx context.Context, ic *types.InvocationContext, req *types.LLMRequest) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		llmAgent, ok := ic.Agent.(*agent.LLMAgent)
		if !ok {
			return
		}

		transferTargets := rp.getTransferTargets(llmAgent)
		if len(transferTargets) == 0 {
			return
		}

		req.AppendInstructions(rp.buildTargetAgentsInstructions(llmAgent, transferTargets))

		// TODO(zchee): use FunctionTool
		// transfer_to_agent_tool = FunctionTool(func=transfer_to_agent)
		var transferToAgentTool types.Tool
		toolCtx := types.NewToolContext(ic)
		transferToAgentTool.ProcessLLMRequest(toolCtx, req)

		// [iter.Seq2] requires yield statement in function body
		// TODO(zchee): need it?
		yield(nil, nil)
	}
}

func (rp *AgentTransferLlmRequestProcessor) buildTargetAgentsInfo(targetAgent types.Agent) string {
	return fmt.Sprintf(`
Agent name: %s
Agent description: %s
`, targetAgent.Name(), targetAgent.Description())

}

func (rp *AgentTransferLlmRequestProcessor) buildTargetAgentsInstructions(llmAgent *agent.LLMAgent, targetAgents []types.Agent) string {
	targetAgentsInfos := make([]string, len(targetAgents))
	for i, targetAgent := range targetAgents {
		targetAgentsInfos[i] = rp.buildTargetAgentsInfo(targetAgent)
	}

	sysInst := `You have a list of other agents to transfer to:

` +
		strings.Join(targetAgentsInfos, "\n") + `


If you are the best to answer the question according to your description, you
can answer it.

If another agent is better for answering the question according to its
description, call ` + "transfer_to_agent" + ` function to transfer the
question to that agent. When transferring, do not generate any text other than
the function call.
`

	if llmAgent.ParentAgent() != nil {
		sysInst += `
Your parent agent is ` + llmAgent.ParentAgent().Name() + `. If neither the other agents nor
you are best for answering the question according to the descriptions, transfer
to your parent agent. If you don't have parent agent, try answer by yourself.
`
	}

	return sysInst
}

func (rp *AgentTransferLlmRequestProcessor) getTransferTargets(llmAgent *agent.LLMAgent) []types.Agent {
	agents := llmAgent.SubAgents()

	if _, ok := llmAgent.ParentAgent().(*agent.LLMAgent); !ok {
		return agents
	}

	if !llmAgent.DisallowTransferToParent() {
		agents = append(agents, llmAgent.ParentAgent())
	}

	if !llmAgent.DisallowTransferToPeers() {
		for _, subAgent := range llmAgent.ParentAgent().SubAgents() {
			if subAgent.Name() != llmAgent.Name() {
				agents = append(agents, subAgent)
			}
		}
	}

	return agents
}
