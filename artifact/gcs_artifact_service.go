// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

// GcsArtifactService is an implementation of ArtifactService using Google Cloud Storage.
type GcsArtifactService struct {
	client     *storage.Client
	bucketName string
	bucket     *storage.BucketHandle
}

// NewGcsArtifactService creates a new GCS artifact service.
func NewGcsArtifactService(ctx context.Context, bucketName string) (*GcsArtifactService, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %w", err)
	}

	return &GcsArtifactService{
		client:     client,
		bucketName: bucketName,
		bucket:     client.Bucket(bucketName),
	}, nil
}

// getBlobName constructs the blob name in GCS.
func (s *GcsArtifactService) getBlobName(appName, userID, sessionID, filename string, version int) string {
	if fileHasUserNamespace(filename) {
		return fmt.Sprintf("%s/%s/user/%s/%d", appName, userID, filename, version)
	}
	return fmt.Sprintf("%s/%s/%s/%s/%d", appName, userID, sessionID, filename, version)
}

// SaveArtifact implements ArtifactService.SaveArtifact.
func (s *GcsArtifactService) SaveArtifact(
	ctx context.Context,
	appName, userID, sessionID, filename string,
	artifact *Part,
) (int, error) {
	versions, err := s.ListVersions(ctx, appName, userID, sessionID, filename)
	if err != nil {
		return 0, fmt.Errorf("failed to list versions: %w", err)
	}

	version := 0
	if len(versions) > 0 {
		version = versions[len(versions)-1] + 1
	}

	blobName := s.getBlobName(appName, userID, sessionID, filename, version)
	obj := s.bucket.Object(blobName)

	w := obj.NewWriter(ctx)
	w.ContentType = artifact.MimeType

	if _, err := w.Write(artifact.Data); err != nil {
		w.Close()
		return 0, fmt.Errorf("failed to write data: %w", err)
	}

	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("failed to close writer: %w", err)
	}

	return version, nil
}

// LoadArtifact implements ArtifactService.LoadArtifact.
func (s *GcsArtifactService) LoadArtifact(
	ctx context.Context,
	appName, userID, sessionID, filename string,
	version *int,
) (*Part, error) {
	var v int
	if version == nil {
		versions, err := s.ListVersions(ctx, appName, userID, sessionID, filename)
		if err != nil {
			return nil, fmt.Errorf("failed to list versions: %w", err)
		}

		if len(versions) == 0 {
			return nil, nil
		}

		v = versions[len(versions)-1]
	} else {
		v = *version
	}

	blobName := s.getBlobName(appName, userID, sessionID, filename, v)
	obj := s.bucket.Object(blobName)

	attrs, err := obj.Attrs(ctx)
	if err == storage.ErrObjectNotExist {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get object attributes: %w", err)
	}

	r, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create reader: %w", err)
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return &Part{
		Data:     data,
		MimeType: attrs.ContentType,
		Filename: filename,
	}, nil
}

// ListArtifactKeys implements ArtifactService.ListArtifactKeys.
func (s *GcsArtifactService) ListArtifactKeys(
	ctx context.Context,
	appName, userID, sessionID string,
) ([]string, error) {
	filenames := make(map[string]struct{})

	// List objects in session namespace
	sessionPrefix := fmt.Sprintf("%s/%s/%s/", appName, userID, sessionID)
	it := s.bucket.Objects(ctx, &storage.Query{Prefix: sessionPrefix})

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list objects in session namespace: %w", err)
		}

		parts := strings.Split(strings.TrimPrefix(attrs.Name, sessionPrefix), "/")
		if len(parts) > 0 {
			filenames[parts[0]] = struct{}{}
		}
	}

	// List objects in user namespace
	userPrefix := fmt.Sprintf("%s/%s/user/", appName, userID)
	it = s.bucket.Objects(ctx, &storage.Query{Prefix: userPrefix})

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list objects in user namespace: %w", err)
		}

		parts := strings.Split(strings.TrimPrefix(attrs.Name, userPrefix), "/")
		if len(parts) > 0 {
			filenames[parts[0]] = struct{}{}
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
func (s *GcsArtifactService) DeleteArtifact(
	ctx context.Context,
	appName, userID, sessionID, filename string,
) error {
	versions, err := s.ListVersions(ctx, appName, userID, sessionID, filename)
	if err != nil {
		return fmt.Errorf("failed to list versions: %w", err)
	}

	for _, version := range versions {
		blobName := s.getBlobName(appName, userID, sessionID, filename, version)
		obj := s.bucket.Object(blobName)

		if err := obj.Delete(ctx); err != nil && err != storage.ErrObjectNotExist {
			return fmt.Errorf("failed to delete object %s: %w", blobName, err)
		}
	}

	return nil
}

// ListVersions implements ArtifactService.ListVersions.
func (s *GcsArtifactService) ListVersions(
	ctx context.Context,
	appName, userID, sessionID, filename string,
) ([]int, error) {
	prefix := path.Dir(s.getBlobName(appName, userID, sessionID, filename, 0)) + "/"
	it := s.bucket.Objects(ctx, &storage.Query{Prefix: prefix})

	versions := []int{}
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		versionStr := path.Base(attrs.Name)
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			continue // Skip objects with non-numeric version
		}

		versions = append(versions, version)
	}

	sort.Ints(versions)
	return versions, nil
}

// Close closes the GCS client.
func (s *GcsArtifactService) Close() error {
	return s.client.Close()
}

// GetArtifact implements ArtifactService.GetArtifact.
func (s *GcsArtifactService) GetArtifact(ctx context.Context, key string) (string, error) {
	// Split the key by ":" to determine if it's a memory key
	parts := strings.SplitN(key, ":", 2)
	if len(parts) < 2 || parts[0] != "memory" {
		return "", fmt.Errorf("invalid memory key format: %s", key)
	}

	memoryKey := parts[1]

	// Construct a memory blob path
	blobName := fmt.Sprintf("memory/%s", memoryKey)
	it := s.bucket.Objects(ctx, &storage.Query{Prefix: blobName})

	var latestVersion int
	var latestAttrs *storage.ObjectAttrs

	// Find the latest version
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to list memory objects: %w", err)
		}

		versionStr := path.Base(attrs.Name)
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			continue // Skip objects with non-numeric version
		}

		if latestAttrs == nil || version > latestVersion {
			latestVersion = version
			latestAttrs = attrs
		}
	}

	if latestAttrs == nil {
		return "", nil // No memory found
	}

	// Read the latest version
	obj := s.bucket.Object(latestAttrs.Name)
	r, err := obj.NewReader(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to read memory object: %w", err)
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read memory data: %w", err)
	}

	return string(data), nil
}

// SaveArtifactByKey implements the simplified version of artifact saving.
func (s *GcsArtifactService) SaveArtifactByKey(ctx context.Context, key string, value string) error {
	// Split the key by ":" to determine if it's a memory key
	parts := strings.SplitN(key, ":", 2)
	if len(parts) < 2 || parts[0] != "memory" {
		return fmt.Errorf("invalid memory key format: %s", key)
	}

	memoryKey := parts[1]

	// Construct a memory blob path
	blobPrefix := fmt.Sprintf("memory/%s", memoryKey)
	it := s.bucket.Objects(ctx, &storage.Query{Prefix: blobPrefix})

	// Find the highest version
	version := 0
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list memory objects: %w", err)
		}

		versionStr := path.Base(attrs.Name)
		v, err := strconv.Atoi(versionStr)
		if err != nil {
			continue // Skip objects with non-numeric version
		}

		if v >= version {
			version = v + 1
		}
	}

	// Write the new version
	blobName := fmt.Sprintf("%s/%d", blobPrefix, version)
	obj := s.bucket.Object(blobName)

	w := obj.NewWriter(ctx)
	w.ContentType = "text/plain"

	if _, err := w.Write([]byte(value)); err != nil {
		w.Close()
		return fmt.Errorf("failed to write memory data: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
	}

	return nil
}

// ListArtifacts implements ArtifactService.ListArtifacts.
func (s *GcsArtifactService) ListArtifacts(ctx context.Context, path string, recursive bool) ([]string, error) {
	var result []string

	// If path doesn't end with slash and it's not empty, add slash
	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	it := s.bucket.Objects(ctx, &storage.Query{Prefix: path})

	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		objectPath := attrs.Name

		// If non-recursive, check if this is a direct child
		if !recursive {
			relative := strings.TrimPrefix(objectPath, path)
			if strings.Contains(relative, "/") {
				continue
			}
		}

		result = append(result, objectPath)
	}

	sort.Strings(result)
	return result, nil
}
