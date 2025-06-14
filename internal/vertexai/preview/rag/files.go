// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package rag

import (
	"context"
	"fmt"
	"log/slog"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/aiplatform/apiv1beta1/aiplatformpb"
	"google.golang.org/api/iterator"
)

// FileService handles file management operations for RAG corpora.
type FileService struct {
	ragClient     *aiplatform.VertexRagClient
	ragDataClient *aiplatform.VertexRagDataClient
	projectID     string
	location      string
	logger        *slog.Logger
}

// NewFileService creates a new FileService.
func NewFileService(ragClient *aiplatform.VertexRagClient, ragDataClient *aiplatform.VertexRagDataClient, projectID, location string, logger *slog.Logger) *FileService {
	if logger == nil {
		logger = slog.Default()
	}
	return &FileService{
		ragClient:     ragClient,
		ragDataClient: ragDataClient,
		projectID:     projectID,
		location:      location,
		logger:        logger,
	}
}

// ImportFiles imports files into a RAG corpus from various sources.
func (s *FileService) ImportFiles(ctx context.Context, req *ImportFilesRequest) error {
	s.logger.InfoContext(ctx, "Importing files into RAG corpus",
		slog.String("parent", req.Parent),
		slog.Int("chunk_size", int(req.ImportFilesConfig.ChunkSize)),
		slog.Int("chunk_overlap", int(req.ImportFilesConfig.ChunkOverlap)),
	)

	pbReq := &aiplatformpb.ImportRagFilesRequest{
		Parent:               req.Parent,
		ImportRagFilesConfig: convertImportFilesConfigToPb(req.ImportFilesConfig),
	}

	op, err := s.ragDataClient.ImportRagFiles(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("failed to import RAG files: %w", err)
	}

	resp, err := op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("failed to wait for RAG files import: %w", err)
	}

	s.logger.InfoContext(ctx, "Files imported successfully",
		slog.Int("imported_count", int(resp.GetImportedRagFilesCount())),
		slog.Int("failed_count", int(resp.GetFailedRagFilesCount())),
	)

	return nil
}

// UploadFile uploads a file directly to a RAG corpus.
func (s *FileService) UploadFile(ctx context.Context, req *UploadFileRequest) (*RagFile, error) {
	s.logger.InfoContext(ctx, "Uploading file to RAG corpus",
		slog.String("parent", req.Parent),
		slog.String("display_name", req.RagFile.DisplayName),
	)

	pbReq := &aiplatformpb.UploadRagFileRequest{
		Parent:  req.Parent,
		RagFile: convertRagFileToPb(req.RagFile),
	}

	if req.UploadRagFileConfig != nil {
		pbReq.UploadRagFileConfig = convertUploadRagFileConfigToPb(req.UploadRagFileConfig)
	}

	resp, err := s.ragDataClient.UploadRagFile(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("failed to upload RAG file: %w", err)
	}

	ragFile := convertPbToRagFile(resp.GetRagFile())
	s.logger.InfoContext(ctx, "File uploaded successfully",
		slog.String("name", ragFile.Name),
		slog.String("display_name", ragFile.DisplayName),
	)

	return ragFile, nil
}

// ListFiles lists all files in a RAG corpus.
func (s *FileService) ListFiles(ctx context.Context, req *ListFilesRequest) (*ListFilesResponse, error) {
	s.logger.InfoContext(ctx, "Listing files in RAG corpus",
		slog.String("parent", req.Parent),
		slog.Int("page_size", int(req.PageSize)),
	)

	pbReq := &aiplatformpb.ListRagFilesRequest{
		Parent:    req.Parent,
		PageSize:  req.PageSize,
		PageToken: req.PageToken,
	}

	it := s.ragDataClient.ListRagFiles(ctx, pbReq)
	var files []*RagFile
	var nextPageToken string

	for {
		pbFile, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list RAG files: %w", err)
		}

		file := convertPbToRagFile(pbFile)
		files = append(files, file)
	}

	// Get next page token if available
	resp := it.Response
	if resp != nil {
		if listResp, ok := resp.(*aiplatformpb.ListRagFilesResponse); ok {
			nextPageToken = listResp.GetNextPageToken()
		}
	}

	s.logger.InfoContext(ctx, "Listed files successfully",
		slog.Int("count", len(files)),
	)

	return &ListFilesResponse{
		RagFiles:      files,
		NextPageToken: nextPageToken,
	}, nil
}

// GetFile retrieves a specific file from a RAG corpus.
func (s *FileService) GetFile(ctx context.Context, name string) (*RagFile, error) {
	s.logger.InfoContext(ctx, "Getting RAG file",
		slog.String("name", name),
	)

	pbReq := &aiplatformpb.GetRagFileRequest{
		Name: name,
	}

	pbFile, err := s.ragDataClient.GetRagFile(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get RAG file: %w", err)
	}

	file := convertPbToRagFile(pbFile)
	s.logger.InfoContext(ctx, "Got RAG file successfully",
		slog.String("name", file.Name),
		slog.String("display_name", file.DisplayName),
	)

	return file, nil
}

// DeleteFile deletes a file from a RAG corpus.
func (s *FileService) DeleteFile(ctx context.Context, req *DeleteFileRequest) error {
	s.logger.InfoContext(ctx, "Deleting RAG file",
		slog.String("name", req.Name),
	)

	pbReq := &aiplatformpb.DeleteRagFileRequest{
		Name: req.Name,
	}

	op, err := s.ragDataClient.DeleteRagFile(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("failed to delete RAG file: %w", err)
	}

	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("failed to wait for RAG file deletion: %w", err)
	}

	s.logger.InfoContext(ctx, "RAG file deleted successfully",
		slog.String("name", req.Name),
	)

	return nil
}

// convertImportFilesConfigToPb converts our ImportFilesConfig to protobuf.
func convertImportFilesConfigToPb(config *ImportFilesConfig) *aiplatformpb.ImportRagFilesConfig {
	if config == nil {
		return nil
	}

	pbConfig := &aiplatformpb.ImportRagFilesConfig{
		MaxEmbeddingRequestsPerMin: config.MaxEmbeddingRequestsPerMin,
	}

	if config.GcsSource != nil {
		pbConfig.ImportSource = &aiplatformpb.ImportRagFilesConfig_GcsSource{
			GcsSource: &aiplatformpb.GcsSource{
				Uris: config.GcsSource.Uris,
			},
		}
	}

	if config.GoogleDriveSource != nil {
		pbConfig.ImportSource = &aiplatformpb.ImportRagFilesConfig_GoogleDriveSource{
			GoogleDriveSource: &aiplatformpb.GoogleDriveSource{
				ResourceIds: convertResourceIdsToProto(config.GoogleDriveSource.ResourceIds),
			},
		}
	}

	return pbConfig
}

// convertResourceIdsToProto converts string resource IDs to protobuf ResourceId format.
func convertResourceIdsToProto(resourceIds []string) []*aiplatformpb.GoogleDriveSource_ResourceId {
	var protoIds []*aiplatformpb.GoogleDriveSource_ResourceId
	for _, id := range resourceIds {
		protoIds = append(protoIds, &aiplatformpb.GoogleDriveSource_ResourceId{
			ResourceId:   id,
			ResourceType: aiplatformpb.GoogleDriveSource_ResourceId_RESOURCE_TYPE_FILE, // Default to file
		})
	}
	return protoIds
}

// convertProtoResourceIdsToStrings converts protobuf ResourceId format back to string slice.
func convertProtoResourceIdsToStrings(protoIds []*aiplatformpb.GoogleDriveSource_ResourceId) []string {
	var resourceIds []string
	for _, protoId := range protoIds {
		resourceIds = append(resourceIds, protoId.GetResourceId())
	}
	return resourceIds
}

// convertUploadRagFileConfigToPb converts our UploadRagFileConfig to protobuf.
func convertUploadRagFileConfigToPb(config *UploadRagFileConfig) *aiplatformpb.UploadRagFileConfig {
	if config == nil {
		return nil
	}

	return &aiplatformpb.UploadRagFileConfig{
		RagFileChunkingConfig: &aiplatformpb.RagFileChunkingConfig{
			ChunkSize:    config.ChunkSize,
			ChunkOverlap: config.ChunkOverlap,
		},
	}
}

// convertRagFileToPb converts our RagFile to protobuf.
func convertRagFileToPb(file *RagFile) *aiplatformpb.RagFile {
	if file == nil {
		return nil
	}

	pbFile := &aiplatformpb.RagFile{
		Name:        file.Name,
		DisplayName: file.DisplayName,
		Description: file.Description,
		SizeBytes:   file.SizeBytes,
		// RagFileType is output only, so we don't set it in creation requests
	}

	setRagFileSource(pbFile, file.RagFileSource)

	return pbFile
}

// setRagFileSource sets the appropriate source field on the RagFile protobuf.
func setRagFileSource(pbFile *aiplatformpb.RagFile, source *RagFileSource) {
	if source == nil {
		return
	}

	if source.GcsSource != nil {
		pbFile.RagFileSource = &aiplatformpb.RagFile_GcsSource{
			GcsSource: &aiplatformpb.GcsSource{
				Uris: source.GcsSource.Uris,
			},
		}
	} else if source.GoogleDriveSource != nil {
		pbFile.RagFileSource = &aiplatformpb.RagFile_GoogleDriveSource{
			GoogleDriveSource: &aiplatformpb.GoogleDriveSource{
				ResourceIds: convertResourceIdsToProto(source.GoogleDriveSource.ResourceIds),
			},
		}
	} else if source.DirectUploadSource != nil {
		pbFile.RagFileSource = &aiplatformpb.RagFile_DirectUploadSource{
			DirectUploadSource: &aiplatformpb.DirectUploadSource{},
		}
	}
}

// convertPbToRagFile converts protobuf RagFile to our RagFile type.
func convertPbToRagFile(pb *aiplatformpb.RagFile) *RagFile {
	if pb == nil {
		return nil
	}

	file := &RagFile{
		Name:        pb.GetName(),
		DisplayName: pb.GetDisplayName(),
		Description: pb.GetDescription(),
		SizeBytes:   pb.GetSizeBytes(),
		RagFileType: pb.GetRagFileType().String(),
	}

	if pb.GetCreateTime() != nil {
		createTime := pb.GetCreateTime().AsTime()
		file.CreateTime = &createTime
	}

	if pb.GetUpdateTime() != nil {
		updateTime := pb.GetUpdateTime().AsTime()
		file.UpdateTime = &updateTime
	}

	// Convert state from file status
	if pb.GetFileStatus() != nil {
		switch pb.GetFileStatus().GetState() {
		case aiplatformpb.FileStatus_ACTIVE:
			file.State = FileStateActive
		case aiplatformpb.FileStatus_ERROR:
			file.State = FileStateError
		default:
			file.State = FileStateUnspecified
		}
	}

	// Convert file source
	if pb.GetRagFileSource() != nil {
		file.RagFileSource = convertPbToRagFileSource(pb)
	}

	return file
}

// convertPbToRagFileSource converts protobuf RagFile to our RagFileSource type.
func convertPbToRagFileSource(pb *aiplatformpb.RagFile) *RagFileSource {
	if pb == nil {
		return nil
	}

	source := &RagFileSource{}

	switch ragFileSource := pb.GetRagFileSource().(type) {
	case *aiplatformpb.RagFile_GcsSource:
		source.GcsSource = &GcsSource{
			Uris: ragFileSource.GcsSource.GetUris(),
		}
	case *aiplatformpb.RagFile_GoogleDriveSource:
		source.GoogleDriveSource = &GoogleDriveSource{
			ResourceIds: convertProtoResourceIdsToStrings(ragFileSource.GoogleDriveSource.GetResourceIds()),
		}
	case *aiplatformpb.RagFile_DirectUploadSource:
		source.DirectUploadSource = &DirectUploadSource{}
	}

	return source
}

// generateFileName generates a file resource name.
func (s *FileService) generateFileName(corpusName, fileID string) string {
	return fmt.Sprintf("%s/ragFiles/%s", corpusName, fileID)
}

// parseFileName parses a file resource name to extract the file ID.
func (s *FileService) parseFileName(name string) (string, error) {
	// Format: projects/{project}/locations/{location}/ragCorpora/{rag_corpus}/ragFiles/{rag_file}
	// This is a simplified parser - you might want to use a more robust implementation
	return name, nil
}
