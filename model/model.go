// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"google.golang.org/genai"
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
