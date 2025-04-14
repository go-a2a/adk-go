// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package codeexecutor

import (
	"encoding/base64"
	"regexp"
	"strings"
	"time"
)

// CodeExecutionUtils provides utility functions for code execution.
type CodeExecutionUtils struct{}

// NewCodeExecutionUtils creates a new CodeExecutionUtils.
func NewCodeExecutionUtils() *CodeExecutionUtils {
	return &CodeExecutionUtils{}
}

// GetEncodedFileContent converts file content to base64-encoded bytes.
func (u *CodeExecutionUtils) GetEncodedFileContent(data []byte) []byte {
	// Check if data is already base64 encoded
	_, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		return data
	}

	// Encode to base64
	return []byte(base64.StdEncoding.EncodeToString(data))
}

// ExtractCodeAndTruncateContent extracts the first code block from content.
func (u *CodeExecutionUtils) ExtractCodeAndTruncateContent(content string, delimiters []CodeBlockDelimiter) (string, string) {
	for _, delimiter := range delimiters {
		regexPattern := regexp.QuoteMeta(delimiter.Start) + "\\s*\\n([\\s\\S]*?)" + regexp.QuoteMeta(delimiter.End)
		regex := regexp.MustCompile(regexPattern)

		matches := regex.FindStringSubmatch(content)
		if len(matches) > 1 {
			code := strings.TrimSpace(matches[1])

			// Truncate content after the code block
			loc := regex.FindStringIndex(content)
			truncatedContent := content[loc[1]:]

			return code, truncatedContent
		}
	}

	return "", content
}

// BuildExecutableCodePart creates a Python executable code part.
func (u *CodeExecutionUtils) BuildExecutableCodePart(code string) string {
	return code
}

// BuildCodeExecutionResultPart generates a result part from code execution.
func (u *CodeExecutionUtils) BuildCodeExecutionResultPart(result CodeExecutionResult, delimiters []ExecutionResultDelimiter) string {
	if len(delimiters) == 0 {
		return ""
	}

	delimiter := delimiters[0]
	var builder strings.Builder

	builder.WriteString(delimiter.Start)
	builder.WriteString("\n")

	// Add timestamp
	builder.WriteString("Timestamp: " + result.Timestamp.Format(time.RFC3339) + "\n")

	// Add stdout if it exists
	if result.Stdout != "" {
		builder.WriteString("\nStdout:\n")
		builder.WriteString(result.Stdout)
	}

	// Add stderr if it exists
	if result.Stderr != "" {
		builder.WriteString("\nStderr:\n")
		builder.WriteString(result.Stderr)
	}

	// Add error if it exists
	if result.Error != "" {
		builder.WriteString("\nError:\n")
		builder.WriteString(result.Error)
	}

	// Add output files if they exist
	if len(result.OutputFiles) > 0 {
		builder.WriteString("\nOutput Files:\n")
		for _, file := range result.OutputFiles {
			builder.WriteString("- " + file.Name + "\n")
		}
	}

	builder.WriteString("\n" + delimiter.End)
	return builder.String()
}

// ConvertCodeExecutionParts converts code execution parts to text parts.
func (u *CodeExecutionUtils) ConvertCodeExecutionParts(content string, codeDelimiters []CodeBlockDelimiter, resultDelimiters []ExecutionResultDelimiter) string {
	// This is a simplified implementation
	// In a real implementation, this would parse and transform code blocks and result blocks
	return content
}
