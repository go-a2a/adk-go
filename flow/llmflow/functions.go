// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package llmflow

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/google/uuid"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/internal/pool"
	"github.com/go-a2a/adk-go/internal/xmaps"
	"github.com/go-a2a/adk-go/pkg/py"
	"github.com/go-a2a/adk-go/pkg/py/pyasyncio"
	"github.com/go-a2a/adk-go/types"
)

const (
	FunctionCallIDPrefix       = "adk-"
	RequestEUCFunctionCallName = "adk_request_credential"
)

// GenerateClientFunctioncallID generates a unique function call ID for the client.
func GenerateClientFunctioncallID() string {
	return FunctionCallIDPrefix + uuid.NewString()
}

// PopulateClientFunctionCallID populates the function call ID for each function call in the model response event.
func PopulateClientFunctionCallID(ctx context.Context, modelResponseEvent *types.Event) {
	funcCalls := modelResponseEvent.GetFunctionCalls()
	if len(funcCalls) == 0 {
		return
	}

	for i := range funcCalls {
		if funcCalls[i].ID == "" {
			funcCalls[i].ID = GenerateClientFunctioncallID()
		}
	}
}

// RemoveClientFunctionCallID removes the function call ID for each function call in the model response event.
func RemoveClientFunctionCallID(content *genai.Content) *genai.Content {
	if content != nil && len(content.Parts) > 0 {
		for i, part := range content.Parts {
			if part.FunctionCall != nil && part.FunctionCall.ID != "" && strings.HasPrefix(part.FunctionCall.ID, FunctionCallIDPrefix) {
				content.Parts[i].FunctionCall.ID = ""
			}

			if part.FunctionResponse != nil && part.FunctionResponse.ID != "" && strings.HasPrefix(part.FunctionResponse.ID, FunctionCallIDPrefix) {
				content.Parts[i].FunctionResponse.ID = ""
			}
		}
	}
	return content
}

// GetLongRunningFunctionCalls returns a set of long-running function call IDs from the given function calls.
func GetLongRunningFunctionCalls(ctx context.Context, funcCalls []*genai.FunctionCall, toolsDict map[string]types.Tool) py.Set[string] {
	longRunningToolIDs := py.NewSet[string]()

	for _, funcCall := range funcCalls {
		if _, ok := toolsDict[funcCall.Name]; ok {
			if toolsDict[funcCall.Name] != nil && toolsDict[funcCall.Name].IsLongRunning() {
				longRunningToolIDs.Insert(funcCall.ID)
			}
		}
	}

	return longRunningToolIDs
}

// GenerateAuthEvent generates an authentication event for the given function response event.
func GenerateAuthEvent(ctx context.Context, ictx *types.InvocationContext, funcResponseEvent *types.Event) (*types.Event, error) {
	if funcResponseEvent.Actions.RequestedAuthConfigs != nil {
		return nil, nil
	}

	var parts []*genai.Part
	longRunningToolIDs := py.NewSet[string]()
	buf := pool.Buffer.Get()
	for funcCallID, config := range funcResponseEvent.Actions.RequestedAuthConfigs {
		authToolArgs := &types.AuthToolArguments{
			FunctionCallID: funcCallID,
			AuthConfig:     config,
		}

		buf.Reset() // reuse
		if err := json.MarshalWrite(buf, authToolArgs, json.DefaultOptionsV2()); err != nil {
			return nil, err
		}

		var m map[string]any
		if err := json.UnmarshalRead(buf, &m, json.DefaultOptionsV2()); err != nil {
			return nil, err
		}
		requestEucFunctionCall := &genai.FunctionCall{
			Name: RequestEUCFunctionCallName,
			Args: m,
		}

		requestEucFunctionCall.ID = GenerateClientFunctioncallID()
		longRunningToolIDs.Insert(requestEucFunctionCall.ID)
		parts = append(parts, &genai.Part{
			FunctionCall: requestEucFunctionCall,
		})
	}
	pool.Buffer.Put(buf)

	return &types.Event{
		LLMResponse: &types.LLMResponse{
			Content: genai.NewContentFromParts(parts, genai.Role(funcResponseEvent.Content.Role)),
		},
		InvocationID:       ictx.InvocationID,
		Author:             ictx.Agent.Name(),
		Branch:             ictx.Branch,
		LongRunningToolIDs: longRunningToolIDs,
	}, nil
}

// HandleFunctionCalls processes function calls asynchronously.
func HandleFunctionCalls(ctx context.Context, ictx *types.InvocationContext, functionCallEvent *types.Event, toolsDict map[string]types.Tool, filters py.Set[string]) (*types.Event, error) {
	// Check if context is already canceled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	llmAgent, ok := ictx.Agent.AsLLMAgent()
	if !ok {
		return nil, nil
	}

	// Extract function calls from event
	funcResponseEvents := []*types.Event{}
	funcCalls := functionCallEvent.GetFunctionCalls()

	// Create result channels
	resultCh := make(chan *types.Event, 1)
	errCh := make(chan error, 1)

	go func() {
		for _, funcCall := range funcCalls {
			if !filters.Has(funcCall.ID) {
				continue
			}
			t, toolCtx, err := getToolAndContext(ctx, ictx, funcCall, toolsDict)
			if err != nil {
				errCh <- err
				return
			}

			funcArgs := funcCall.Args
			var funcResponse map[string]any
			for i, callback := range llmAgent.BeforeToolCallback() {
				funcResponse, err = callback(t, funcArgs, toolCtx)
				if err != nil {
					errCh <- fmt.Errorf("BeforeToolCallbacks[%d]: %w", i, err)
					return
				}
				// TODO(zchee): wait for complete with [py.Future]
				// if inspect.isawaitable(function_response):
				//   function_response = await function_response
				if len(funcResponse) == 0 {
					break
				}
			}

			if len(funcResponse) == 0 {
				funcResponse, err = callTool(ctx, t, funcArgs, toolCtx)
				if err != nil {
					errCh <- err
					return
				}
			}

			for i, callback := range llmAgent.AfterToolCallbacks() {
				funcResp, err := callback(t, funcArgs, toolCtx, funcResponse)
				if err != nil {
					errCh <- fmt.Errorf("BeforeToolCallbacks[%d]: %w", i, err)
					return
				}
				// TODO(zchee): wait for complete with [py.Future]
				// if inspect.isawaitable(function_response):
				//   function_response = await function_response
				if len(funcResp) > 0 {
					funcResponse = funcResp
					break
				}

				if t.IsLongRunning() && len(funcResponse) == 0 {
					continue
				}

				// Builds the function response event
				funcResponseEvent := buildResponseEvent(ctx, t, funcResponse, toolCtx, ictx)
				funcResponseEvents = append(funcResponseEvents, funcResponseEvent)
			}
		}

		if len(funcResponseEvents) == 0 {
			return
		}

		mergedEvent, err := mergeParallelFunctionResponseEvents(funcResponseEvents)
		if err != nil {
			errCh <- err
			return
		}

		if len(funcResponseEvents) > 1 {
			// TODO(zchee): support OTel tracing
		}

		resultCh <- mergedEvent
	}()

	// Wait for result or cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, err
	case mergedEvent := <-resultCh:
		return mergedEvent, nil
	}
}

// HandleFunctionCallsLive calls the functions and returns the function response event.
func HandleFunctionCallsLive(ctx context.Context, ictx *types.InvocationContext, functionCallEvent *types.Event, toolsDict map[string]types.Tool) (*types.Event, error) {
	// Check if context is already canceled
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	llmAgent, ok := ictx.Agent.AsLLMAgent()
	if !ok {
		return nil, nil
	}

	funcCalls := functionCallEvent.GetFunctionCalls()
	var funcResponseEvents []*types.Event
	for _, funcCall := range funcCalls {
		t, toolCtx, err := getToolAndContext(ctx, ictx, funcCall, toolsDict)
		if err != nil {
			return nil, err
		}

		funcArgs := funcCall.Args
		var functResponse map[string]any
		if callbacks := llmAgent.BeforeToolCallback(); len(callbacks) > 0 {
			for _, callback := range callbacks {
				functResponse, err = callback(t, funcArgs, toolCtx)
				if err != nil {
					return nil, err
				}
			}
		}
		if len(functResponse) == 0 {
			functResponse = processFunctionLiveHelper(ctx, t, toolCtx, funcCall, funcArgs, ictx)
		}

		if callbacks := llmAgent.AfterToolCallbacks(); len(callbacks) > 0 {
			for _, callback := range callbacks {
				functResponse, err = callback(t, funcArgs, toolCtx, functResponse)
				if err != nil {
					return nil, err
				}
			}
		}

		if t.IsLongRunning() && len(functResponse) == 0 {
			continue
		}

		funcResponseEvents = append(funcResponseEvents, buildResponseEvent(ctx, t, functResponse, toolCtx, ictx))
	}

	var mergedEvent *types.Event
	if len(funcResponseEvents) > 0 {
		var err error
		mergedEvent, err = mergeParallelFunctionResponseEvents(funcResponseEvents)
		if err != nil {
			return nil, err
		}
	}

	return mergedEvent, nil
}

func processFunctionLiveHelper(ctx context.Context, t types.Tool, toolCtx *types.ToolContext, funcCall *genai.FunctionCall, funcArgs map[string]any, ictx *types.InvocationContext) map[string]any {
	funcResponse := make(map[string]any)

	if funcCall.Name == "stop_streaming" && xmaps.Contains(funcArgs, "function_name") {
		functionName := funcArgs["function_name"].(string)
		activeTasks := ictx.ActiveStreamingTools
		if xmaps.Contains(activeTasks, functionName) {
			if atask, ok := activeTasks[functionName]; ok && atask.Task != nil {
				task := atask.Task
				task.Cancel()
				_, err := pyasyncio.WaitForTask(ctx, time.Second, task)
				if err != nil {
					switch {
					case task.Cancelled():
						// Log the specific condition
						slog.Default().InfoContext(ctx, "task was cancelled successfully", slog.String("function_name", functionName))
					case task.Done():
						slog.Default().InfoContext(ctx, "task completed during cancellation", slog.String("function_name", functionName))
					default:
						slog.Default().InfoContext(ctx, "task might still be running after cancellation timeout", slog.String("function_name", functionName))
						funcResponse["status"] = fmt.Sprintf("The task is not cancelled yet for %s.", functionName)
					}
				}
				if len(funcResponse) == 0 {
					// Clean up the reference
					activeTasks[functionName].Task = nil
					funcResponse["status"] = fmt.Sprintf("Successfully stopped streaming function %s.", functionName)
				}
			}
		}
		funcResponse["status"] = fmt.Sprintf("No active streaming function named %s found", functionName)

		return funcResponse
	}

	if _, ok := t.(interface{ Func() }); ok {
		// for streaming tool use case
		// we require the function to be a async generator function
		runToolAndPpdateQueue := func(t types.Tool, funcArgs map[string]any, toolCtx *types.ToolContext) (any, error) {
			results := callToolLive(ctx, t, funcArgs, toolCtx, ictx)
			for result, err := range results {
				if err != nil {
					return nil, err
				}
				updatedContent := genai.NewContentFromText(
					fmt.Sprintf("Function %s returned: %v", t.Name(), &result), genai.Role("user"),
				)
				ictx.LiveRequestQueue.SendContent(updatedContent)
			}
			return nil, nil
		}

		task := pyasyncio.CreateTask(ctx, func(ctx context.Context) (any, error) { return runToolAndPpdateQueue(t, funcArgs, toolCtx) })
		if len(ictx.ActiveStreamingTools) == 0 {
			ictx.ActiveStreamingTools = make(map[string]*types.ActiveStreamingTool[any])
		}
		switch {
		case xmaps.Contains(ictx.ActiveStreamingTools, t.Name()):
			ictx.ActiveStreamingTools[t.Name()].Task = task
		default:
			ictx.ActiveStreamingTools[t.Name()] = types.NewActiveStreamingTool[any]().WithTask(task)
		}

		// Immediately return a pending response.
		// This is required by current live model.
		funcResponse["status"] = "The function is running asynchronously and the results are pending."

		return funcResponse
	}

	resp, err := callTool(ctx, t, funcArgs, toolCtx)
	if err != nil {
		return nil
	}
	funcResponse = resp

	return funcResponse
}

func getToolAndContext(ctx context.Context, ictx *types.InvocationContext, funcCall *genai.FunctionCall, toolsDict map[string]types.Tool) (types.Tool, *types.ToolContext, error) {
	t, ok := toolsDict[funcCall.Name]
	if !ok {
		return nil, nil, fmt.Errorf("Function %s is not found in the tools_dict", funcCall.Name)
	}
	toolCtx := types.NewToolContext(ictx).WithFunctionCallID(funcCall.ID)

	return t, toolCtx, nil
}

// callToolLive calls the tool asynchronously (awaiting the coroutine).
func callToolLive(ctx context.Context, t types.Tool, args map[string]any, toolCtx *types.ToolContext, ictx *types.InvocationContext) iter.Seq2[*types.Event, error] {
	return func(yield func(*types.Event, error) bool) {
		result, err := t.Run(ctx, args, toolCtx)
		if !yield(result.(*types.Event), err) {
			return
		}
	}
}

// callTool calls the tool.
func callTool(ctx context.Context, t types.Tool, args map[string]any, tctx *types.ToolContext) (map[string]any, error) {
	res, err := t.Run(ctx, args, tctx)
	if err != nil {
		return nil, err
	}
	result, ok := res.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("res is not map[string]any: %T", res)
	}

	return result, nil
}

// TODO(zchee): support OTel tracing.
func buildResponseEvent(ctx context.Context, t types.Tool, funcResult map[string]any, toolCtx *types.ToolContext, ictx *types.InvocationContext) *types.Event {
	// specs requires the result to be a dict.
	if len(funcResult) == 0 {
		funcResult = map[string]any{
			"result": funcResult,
		}
	}

	partFuncResponse := genai.NewPartFromFunctionResponse(t.Name(), funcResult)
	partFuncResponse.FunctionResponse.ID = toolCtx.FunctionCallID()

	content := &genai.Content{
		Role:  "user",
		Parts: []*genai.Part{partFuncResponse},
	}

	funcRespEvent := types.NewEvent().
		WithInvocationID(ictx.InvocationID).
		WithAuthor(ictx.Agent.Name()).
		WithContent(content).
		WithActions(toolCtx.Actions()).
		WithBranch(ictx.Branch)

	return funcRespEvent
}

func mergeParallelFunctionResponseEvents(funcRespEvents []*types.Event) (*types.Event, error) {
	switch len(funcRespEvents) {
	case 0:
		return nil, errors.New("no function response events provided")

	case 1:
		return funcRespEvents[0], nil
	}

	var mergedParts []*genai.Part
	for _, event := range funcRespEvents {
		if event.Content != nil {
			for _, part := range event.Content.Parts {
				mergedParts = append(mergedParts, part)
			}
		}
	}

	// Use the first event as the "base" for common attributes
	baseEvent := funcRespEvents[0]

	// Merge actions from all events
	mergedActions := types.NewEventActions()
	mergedRequestedAuthConfigs := make(map[string]*types.AuthConfig)
	for _, event := range funcRespEvents {
		maps.Copy(mergedRequestedAuthConfigs, event.Actions.RequestedAuthConfigs)
	}
	mergedActions.RequestedAuthConfigs = mergedRequestedAuthConfigs

	// Create the new merged event
	mergedEvent := types.NewEvent().
		WithInvocationID(types.NewEventID()).
		WithAuthor(baseEvent.Author).
		WithBranch(baseEvent.Branch).
		WithContent(genai.NewContentFromParts(mergedParts, genai.Role("user"))).
		WithActions(mergedActions)

	// Use the base_event as the timestamp
	mergedEvent.Timestamp = baseEvent.Timestamp

	return mergedEvent, nil
}

// FindMatchingFunctionCall finds the function call event that matches the function response id of the last event.
func FindMatchingFunctionCall(ctx context.Context, events []*types.Event) *types.Event {
	if len(events) == 0 {
		return nil
	}

	lastEvent := events[len(events)-1]
	if lastEvent.Content != nil {
		parts := lastEvent.Content.Parts
		if idx := slices.IndexFunc(parts, func(part *genai.Part) bool { return part.FunctionResponse != nil }); idx >= 0 {
			functionCallID := parts[idx].FunctionCall.ID

			for _, ev := range slices.Backward(events[1:]) {
				functionCalls := ev.GetFunctionCalls()
				if len(functionCalls) == 0 {
					continue
				}
				for _, funcCall := range functionCalls {
					if funcCall.ID == functionCallID {
						return ev
					}
				}
			}
		}
	}

	return nil
}
