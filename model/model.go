// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"net/http"
	"reflect"

	"google.golang.org/genai"
)

const (
	// EnvGoogleCloudProject is the environment variable name that specifies the GCP project ID.
	EnvGoogleCloudProject = "GOOGLE_CLOUD_PROJECT"

	// EnvGoogleCloudProject is the environment variable name that specifies the GCP location.
	EnvGoogleCloudLocation = "GOOGLE_CLOUD_LOCATION"

	// EnvGoogleCloudRegion is the environment variable name that specifies the GCP region.
	EnvGoogleCloudRegion = "GOOGLE_CLOUD_REGION"
)

// Role represents a role of a participant in a conversation.
type Role = string

// NewRole creates a new role from a string type.
func NewRole[T ~string](role T) Role {
	return Role(role)
}

// ToGenAIRole converts a custom role type to a [genai.Role] type.
func ToGenAIRole[T ~string](role T) genai.Role {
	return genai.Role(role)
}

const (
	// RoleSystem is the role of the system.
	RoleSystem Role = "system"

	// RoleUser is the role of the user.
	//
	// This value Same as the [genai.RoleUser]
	RoleUser Role = "user"

	// RoleModel is the role of the model.
	//
	// This value Same as the [genai.RoleModel]
	RoleModel Role = "model"

	// RoleAssistant is the role of the assistant.
	//
	// This value Same as the [anthropic.MessageParamRoleAssistant]
	RoleAssistant Role = "assistant"
)

// Option is a function that modifies the [Gemini] or [Claude] model.
type Option[T Gemini | Claude] func(*T)

var (
	geminiType = reflect.TypeOf(Gemini{})
	claudeType = reflect.TypeOf(Claude{})
)

// WithHTTPClient sets the [*http.Client] for the [Gemini] model.
func WithHTTPClient[T Gemini | Claude](hc *http.Client) Option[T] {
	switch reflect.TypeFor[T]() {
	case geminiType:
		return func(m *T) {
			any(m).(*Gemini).hc = hc
		}
	case claudeType:
		return func(m *T) {
			any(m).(*Claude).hc = hc
		}
	default:
		panic("unreachable")
	}
}
