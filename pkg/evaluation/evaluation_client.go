// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package evaluation

import (
	"fmt"
	"log/slog"
	"strings"
)

// SimpleEvaluationClient is a basic implementation of the EvaluationClient interface.
// In a real-world scenario, this would typically connect to a more sophisticated
// evaluation service like Vertex AI's evaluation framework.
type SimpleEvaluationClient struct {
	Logger *slog.Logger
}

// NewSimpleEvaluationClient creates a new SimpleEvaluationClient.
func NewSimpleEvaluationClient(logger *slog.Logger) *SimpleEvaluationClient {
	if logger == nil {
		logger = slog.Default()
	}

	return &SimpleEvaluationClient{
		Logger: logger,
	}
}

// EvaluateCoherence evaluates response coherence on a scale of 0-5.
// This is a simplified implementation that evaluates based on response length and structure.
func (c *SimpleEvaluationClient) EvaluateCoherence(query, response string) (float64, error) {
	if response == "" {
		return 0.0, nil
	}

	// Simple coherence scoring based on length (for demonstration only)
	// In a real implementation, this would use LLM-based evaluation or other metrics

	// Factor 1: Response length relative to query
	lengthRatio := float64(len(response)) / float64(len(query))
	var lengthScore float64

	if lengthRatio < 0.5 {
		lengthScore = 1.0 // Too short
	} else if lengthRatio > 5.0 {
		lengthScore = 3.0 // Potentially too verbose
	} else {
		lengthScore = 4.0 // Reasonable length
	}

	// Factor 2: Structure - presence of sentences
	sentences := strings.Count(response, ".")
	var structureScore float64

	if sentences == 0 {
		structureScore = 1.0 // No complete sentences
	} else if sentences == 1 {
		structureScore = 3.0 // Single sentence
	} else {
		structureScore = 5.0 // Multiple sentences
	}

	// Factor 3: Addresses query (simplified check for keyword presence)
	keywords := extractKeywords(query)
	keywordMatches := 0

	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(response), strings.ToLower(keyword)) {
			keywordMatches++
		}
	}

	keywordRatio := float64(keywordMatches) / float64(len(keywords))
	var relevanceScore float64

	if keywordRatio == 0 {
		relevanceScore = 1.0 // No keywords found
	} else if keywordRatio < 0.5 {
		relevanceScore = 3.0 // Some keywords found
	} else {
		relevanceScore = 5.0 // Most keywords found
	}

	// Combined score (weighted average)
	finalScore := (lengthScore*0.2 + structureScore*0.3 + relevanceScore*0.5)

	// Log details for debugging
	c.Logger.Debug("Coherence evaluation",
		slog.String("query", query),
		slog.String("response", response),
		slog.Float64("length_score", lengthScore),
		slog.Float64("structure_score", structureScore),
		slog.Float64("relevance_score", relevanceScore),
		slog.Float64("final_score", finalScore))

	return finalScore, nil
}

// EvaluateResponseMatch evaluates response similarity against a reference on a scale of 0-1.
// This is a simplified implementation that uses basic string matching.
func (c *SimpleEvaluationClient) EvaluateResponseMatch(response, reference string) (float64, error) {
	if response == "" || reference == "" {
		return 0.0, fmt.Errorf("empty response or reference")
	}

	// Convert to lowercase for comparison
	responseLower := strings.ToLower(response)
	referenceLower := strings.ToLower(reference)

	// Simple matching techniques (for demonstration only)
	// In a real implementation, this would use embedding similarity or other metrics

	// Exact match check
	if responseLower == referenceLower {
		return 1.0, nil
	}

	// Word overlap
	responseWords := strings.Fields(responseLower)
	referenceWords := strings.Fields(referenceLower)

	// Create maps for word counting
	responseWordMap := make(map[string]int)
	referenceWordMap := make(map[string]int)

	for _, word := range responseWords {
		responseWordMap[word]++
	}

	for _, word := range referenceWords {
		referenceWordMap[word]++
	}

	// Count matching words
	var matchingWords int
	for word, count := range referenceWordMap {
		if responseCount, exists := responseWordMap[word]; exists {
			matchingWords += min(count, responseCount)
		}
	}

	// Calculate Jaccard similarity: intersection / union
	totalWords := len(referenceWords) + len(responseWords) - matchingWords
	if totalWords == 0 {
		return 0.0, nil
	}

	similarity := float64(matchingWords) / float64(totalWords)

	c.Logger.Debug("Response match evaluation",
		slog.String("response", response),
		slog.String("reference", reference),
		slog.Int("matching_words", matchingWords),
		slog.Int("total_words", totalWords),
		slog.Float64("similarity", similarity))

	return similarity, nil
}

// extractKeywords extracts key words from a query for relevance checking.
func extractKeywords(query string) []string {
	// Convert to lowercase and split into words
	words := strings.Fields(strings.ToLower(query))

	// Filter out common stop words
	stopWords := map[string]bool{
		"a": true, "an": true, "the": true, "and": true, "or": true,
		"but": true, "is": true, "are": true, "am": true, "was": true,
		"were": true, "be": true, "been": true, "being": true,
		"in": true, "on": true, "at": true, "to": true, "for": true,
		"with": true, "by": true, "about": true, "like": true,
		"through": true, "over": true, "before": true, "after": true,
		"between": true, "under": true, "during": true, "without": true,
		"of": true, "from": true,
	}

	var keywords []string
	for _, word := range words {
		// Remove any punctuation
		word = strings.Trim(word, ".,!?:;()\"-")

		// Skip empty strings and stop words
		if word == "" || stopWords[word] {
			continue
		}

		keywords = append(keywords, word)
	}

	return keywords
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
