// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"context"
	"testing"

	"github.com/go-a2a/adk-go/session"
)

func TestNewInvocationContext(t *testing.T) {
	ctx := context.Background()
	sess := session.NewSession("test-id", "test-app-name", "test-userID")

	invocationCtx := NewInvocationContext(ctx, sess)

	if invocationCtx.Context != ctx {
		t.Errorf("expected context %v, got %v", ctx, invocationCtx.Context)
	}

	if invocationCtx.Session != sess {
		t.Errorf("expected session %v, got %v", sess, invocationCtx.Session)
	}
}
