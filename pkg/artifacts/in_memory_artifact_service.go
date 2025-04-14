// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package artifacts

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// InMemoryArtifactService is an in-memory implementation of the ArtifactService.
type InMemoryArtifactService struct {
	mu        sync.RWMutex
	artifacts map[string][]*Part
}

var _ ArtifactService = (*InMemoryArtifactService)(nil)

// NewInMemoryArtifactService creates a new in-memory artifact service.
func NewInMemoryArtifactService() *InMemoryArtifactService {
	return &InMemoryArtifactService{
		artifacts: make(map[string][]*Part),
	}
}

// fileHasUserNamespace checks if the filename has a user namespace.
func fileHasUserNamespace(filename string) bool {
	return strings.HasPrefix(filename, "user:")
}

// artifactPath constructs the artifact path.
func artifactPath(appName, userID, sessionID, filename string) string {
	if fileHasUserNamespace(filename) {
		return fmt.Sprintf("%s/%s/user/%s", appName, userID, filename)
	}
	return fmt.Sprintf("%s/%s/%s/%s", appName, userID, sessionID, filename)
}

// SaveArtifact implements ArtifactService.SaveArtifact.
func (s *InMemoryArtifactService) SaveArtifact(
	ctx context.Context,
	appName, userID, sessionID, filename string,
	artifact *Part,
) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := artifactPath(appName, userID, sessionID, filename)

	versions, ok := s.artifacts[path]
	if !ok {
		s.artifacts[path] = []*Part{artifact}
		return 0, nil
	}

	version := len(versions)
	s.artifacts[path] = append(versions, artifact)
	return version, nil
}

// LoadArtifact implements ArtifactService.LoadArtifact.
func (s *InMemoryArtifactService) LoadArtifact(
	ctx context.Context,
	appName, userID, sessionID, filename string,
	version *int,
) (*Part, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := artifactPath(appName, userID, sessionID, filename)

	versions, ok := s.artifacts[path]
	if !ok || len(versions) == 0 {
		return nil, nil
	}

	if version == nil {
		// Return the latest version
		return versions[len(versions)-1], nil
	}

	if *version < 0 || *version >= len(versions) {
		return nil, fmt.Errorf("version out of range: %d", *version)
	}

	return versions[*version], nil
}

// ListArtifactKeys implements ArtifactService.ListArtifactKeys.
func (s *InMemoryArtifactService) ListArtifactKeys(
	ctx context.Context,
	appName, userID, sessionID string,
) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionPrefix := fmt.Sprintf("%s/%s/%s/", appName, userID, sessionID)
	userNamespacePrefix := fmt.Sprintf("%s/%s/user/", appName, userID)

	filenames := make(map[string]struct{})

	for path := range s.artifacts {
		if strings.HasPrefix(path, sessionPrefix) {
			filename := strings.TrimPrefix(path, sessionPrefix)
			filenames[filename] = struct{}{}
		} else if strings.HasPrefix(path, userNamespacePrefix) {
			filename := strings.TrimPrefix(path, userNamespacePrefix)
			filenames[filename] = struct{}{}
		}
	}

	result := make([]string, 0, len(filenames))
	for filename := range filenames {
		result = append(result, filename)
	}

	sort.Strings(result)
	return result, nil
}

// DeleteArtifact implements ArtifactService.DeleteArtifact.
func (s *InMemoryArtifactService) DeleteArtifact(
	ctx context.Context,
	appName, userID, sessionID, filename string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := artifactPath(appName, userID, sessionID, filename)

	_, ok := s.artifacts[path]
	if !ok {
		return nil // Nothing to delete
	}

	delete(s.artifacts, path)
	return nil
}

// ListVersions implements ArtifactService.ListVersions.
func (s *InMemoryArtifactService) ListVersions(
	ctx context.Context,
	appName, userID, sessionID, filename string,
) ([]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	path := artifactPath(appName, userID, sessionID, filename)

	versions, ok := s.artifacts[path]
	if !ok || len(versions) == 0 {
		return []int{}, nil
	}

	result := make([]int, len(versions))
	for i := range versions {
		result[i] = i
	}

	return result, nil
}

// GetArtifact implements ArtifactService.GetArtifact.
func (s *InMemoryArtifactService) GetArtifact(ctx context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions, ok := s.artifacts[key]
	if !ok || len(versions) == 0 {
		return "", nil
	}

	// Return the latest version
	latestVersion := versions[len(versions)-1]
	return string(latestVersion.Data), nil
}

// SaveArtifactByKey implements ArtifactService.SaveArtifactByKey.
func (s *InMemoryArtifactService) SaveArtifactByKey(ctx context.Context, key string, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	part := &Part{
		Data:     []byte(value),
		MimeType: "text/plain",
		Filename: key,
	}

	versions, ok := s.artifacts[key]
	if !ok {
		s.artifacts[key] = []*Part{part}
		return nil
	}

	s.artifacts[key] = append(versions, part)
	return nil
}

// ListArtifacts implements ArtifactService.ListArtifacts.
func (s *InMemoryArtifactService) ListArtifacts(ctx context.Context, path string, recursive bool) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []string
	for key := range s.artifacts {
		if strings.HasPrefix(key, path) {
			// If non-recursive, check if this is a direct child
			if !recursive {
				suffix := strings.TrimPrefix(key, path)
				if strings.Contains(suffix, "/") {
					continue
				}
			}
			result = append(result, key)
		}
	}

	sort.Strings(result)
	return result, nil
}
