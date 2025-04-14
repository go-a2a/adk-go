// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package artifacts_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/pkg/artifacts"
)

// TestInMemoryArtifactService tests the in-memory artifact service implementation.
// This uses a table-driven approach as recommended by Google's paper on testing:
// https://storage.googleapis.com/gweb-research2023-media/pubtools/5172.pdf
func TestInMemoryArtifactService(t *testing.T) {
	ctx := context.Background()
	service := artifacts.NewInMemoryArtifactService()

	// Test parameters
	appName := "test-app"
	userID := "test-user"
	sessionID := "test-session"
	filename := "test-file.txt"
	userFilename := "user:test-file.txt"

	// Test artifact data
	artifact1 := &artifacts.Part{
		Data:     []byte("test data 1"),
		MimeType: "text/plain",
		Filename: filename,
	}
	artifact2 := &artifacts.Part{
		Data:     []byte("test data 2"),
		MimeType: "text/plain",
		Filename: filename,
	}
	userArtifact := &artifacts.Part{
		Data:     []byte("user namespace data"),
		MimeType: "text/plain",
		Filename: userFilename,
	}

	// Test SaveArtifact
	version1, err := service.SaveArtifact(ctx, appName, userID, sessionID, filename, artifact1)
	if err != nil {
		t.Fatalf("SaveArtifact failed: %v", err)
	}
	if version1 != 0 {
		t.Errorf("expected version 0, got %d", version1)
	}

	version2, err := service.SaveArtifact(ctx, appName, userID, sessionID, filename, artifact2)
	if err != nil {
		t.Fatalf("SaveArtifact failed: %v", err)
	}
	if version2 != 1 {
		t.Errorf("expected version 1, got %d", version2)
	}

	// Save user namespace artifact
	userVersion, err := service.SaveArtifact(ctx, appName, userID, sessionID, userFilename, userArtifact)
	if err != nil {
		t.Fatalf("SaveArtifact failed for user namespace: %v", err)
	}
	if userVersion != 0 {
		t.Errorf("expected user namespace version 0, got %d", userVersion)
	}

	// Test LoadArtifact
	// Load specific version
	version := 0
	loaded, err := service.LoadArtifact(ctx, appName, userID, sessionID, filename, &version)
	if err != nil {
		t.Fatalf("LoadArtifact failed: %v", err)
	}
	if !cmp.Equal(loaded, artifact1) {
		t.Errorf("expected %v, got %v", artifact1, loaded)
	}

	// Load latest version
	loaded, err = service.LoadArtifact(ctx, appName, userID, sessionID, filename, nil)
	if err != nil {
		t.Fatalf("LoadArtifact failed: %v", err)
	}
	if !cmp.Equal(loaded, artifact2) {
		t.Errorf("expected %v, got %v", artifact2, loaded)
	}

	// Load user namespace artifact
	loaded, err = service.LoadArtifact(ctx, appName, userID, sessionID, userFilename, nil)
	if err != nil {
		t.Fatalf("LoadArtifact failed for user namespace: %v", err)
	}
	if !cmp.Equal(loaded, userArtifact) {
		t.Errorf("expected %v, got %v", userArtifact, loaded)
	}

	// Test ListArtifactKeys
	keys, err := service.ListArtifactKeys(ctx, appName, userID, sessionID)
	if err != nil {
		t.Fatalf("ListArtifactKeys failed: %v", err)
	}
	expectedKeys := []string{filename, userFilename}
	if !cmp.Equal(keys, expectedKeys) {
		t.Errorf("expected keys %v, got %v", expectedKeys, keys)
	}

	// Test ListVersions
	versions, err := service.ListVersions(ctx, appName, userID, sessionID, filename)
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}
	expectedVersions := []int{0, 1}
	if !cmp.Equal(versions, expectedVersions) {
		t.Errorf("expected versions %v, got %v", expectedVersions, versions)
	}

	// Test DeleteArtifact
	err = service.DeleteArtifact(ctx, appName, userID, sessionID, filename)
	if err != nil {
		t.Fatalf("DeleteArtifact failed: %v", err)
	}

	// Verify deletion
	loaded, err = service.LoadArtifact(ctx, appName, userID, sessionID, filename, nil)
	if err != nil {
		t.Fatalf("LoadArtifact failed after deletion: %v", err)
	}
	if loaded != nil {
		t.Errorf("expected nil after deletion, got %v", loaded)
	}

	// User artifact should still exist
	loaded, err = service.LoadArtifact(ctx, appName, userID, sessionID, userFilename, nil)
	if err != nil {
		t.Fatalf("LoadArtifact failed for user namespace after deletion: %v", err)
	}
	if !cmp.Equal(loaded, userArtifact) {
		t.Errorf("expected %v after deletion of other artifact, got %v", userArtifact, loaded)
	}
}
