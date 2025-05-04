// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

// ActiveStreamingTool manages streaming tool related resources during invocation.
type ActiveStreamingTool struct {
	// Task is the active task of this streaming tool.
	Task any // Optional[asyncio.Task] = None

	// Stream is the active (input) streams of this streaming tool.
	Stream LiveRequestQueue
}
