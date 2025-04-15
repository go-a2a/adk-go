// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package event provides structures and functionality for handling
// conversation events between agents and users in the Agent Development Kit.
//
// Events represent conversational exchanges including user inputs, agent responses,
// and any associated actions or function calls. This package enables tracking of
// conversation state, function call history, and event metadata.
//
// The key components are:
//
// Event: Represents a conversation event, containing content, author information,
// function calls, and associated actions.
//
// EventActions: Contains metadata about actions associated with an event,
// such as state changes, transfers between agents, and authentication requests.
//
// FunctionCall: Represents a function (tool) invocation by an agent, including
// parameters and responses.
package event
