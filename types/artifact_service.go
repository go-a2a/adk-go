// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"

	"google.golang.org/genai"
)

// ArtifactService represents an abstract base class for artifact services.
type ArtifactService interface {
	// SaveArtifact saves an artifact to the artifact service storage.
	//
	// The artifact is a file identified by the app name, user ID, session ID, and
	// filename. After saving the artifact, a revision ID is returned to identify
	// the artifact version.
	SaveArtifact(ctx context.Context, appName, userID, sessionID, filename string, artifact *genai.Part) (int, error)

	// LoadArtifact gets an artifact from the artifact service storage.
	//
	// The artifact is a file identified by the app name, user ID, session ID, and filename.
	LoadArtifact(ctx context.Context, appName, userID, sessionID, filename string, version int) (*genai.Part, error)

	// ListArtifactKey lists all the artifact filenames within a session.
	ListArtifactKey(ctx context.Context, appName, userID, sessionID string) ([]string, error)

	// DeleteArtifact deletes an artifact.
	DeleteArtifact(ctx context.Context, appName, userID, sessionID, filename string) error

	// ListVersions lists all versions of an artifact.
	ListVersions(ctx context.Context, appName, userID, sessionID, filename string) ([]int, error)
}
