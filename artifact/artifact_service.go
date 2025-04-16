// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package artifact provides functionality for storing and retrieving artifacts.
package artifact

import (
	"bytes"
	"context"
	"io"

	"google.golang.org/genai"
)

// Part represents an artifact content with its metadata.
type Part struct {
	Data     []byte
	MimeType string
	Filename string
}

// ArtifactService defines the interface for interacting with artifacts.
type ArtifactService interface {
	// SaveArtifact saves an artifact to the artifact service storage.
	// The artifact is identified by app name, user ID, session ID, and filename.
	// Returns the revision ID to identify the artifact version.
	// The first version of the artifact has a revision ID of 0.
	SaveArtifact(ctx context.Context, appName, userID, sessionID, filename string, artifact *genai.Part) (int, error)

	// LoadArtifact gets an artifact from the artifact service storage.
	// The artifact is identified by app name, user ID, session ID, and filename.
	// If version is nil, the latest version will be returned.
	LoadArtifact(ctx context.Context, appName, userID, sessionID, filename string, version *int) (*genai.Part, error)

	// ListArtifactKeys lists all the artifact filenames within a session.
	ListArtifactKeys(ctx context.Context, appName, userID, sessionID string) ([]string, error)

	// DeleteArtifact deletes an artifact.
	DeleteArtifact(ctx context.Context, appName, userID, sessionID, filename string) error

	// ListVersions lists all versions of an artifact.
	ListVersions(ctx context.Context, appName, userID, sessionID, filename string) ([]int, error)

	// GetArtifact gets an artifact by key.
	// This is a simplified version of LoadArtifact for use with memory tools.
	GetArtifact(ctx context.Context, key string) (string, error)

	// SaveArtifactByKey saves an artifact by key.
	// This is a simplified version of SaveArtifact for use with memory tools.
	SaveArtifactByKey(ctx context.Context, key string, value string) error

	// ListArtifacts lists artifacts at a path, optionally recursively.
	ListArtifacts(ctx context.Context, path string, recursive bool) ([]string, error)
}

// FromReader creates a Part from an [io.Reader].
func FromReader(r io.Reader, mimeType, filename string) (*genai.Part, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return &genai.Part{
		InlineData: &genai.Blob{
			Data:     data,
			MIMEType: mimeType,
		},
	}, nil
}

// Reader returns an [io.Reader] for the Part's data.
func (p *Part) Reader() io.Reader {
	return io.NopCloser(bytes.NewReader(p.Data))
}
