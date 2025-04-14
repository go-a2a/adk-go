// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

// Package flow provides functionality for defining and executing flows
// for language model interaction and agent communication.
//
// The flow package is organized around a processor-based architecture,
// where request and response processors handle different aspects of LLM
// interaction. This includes preparing prompts, handling function calls,
// processing responses, and managing agent interactions.
//
// The key components are:
//
//   - Flow interfaces defining the core functionality for flow execution.
//
//   - LLM flows for language model interaction, including the base flow
//     and specialized flows like SingleFlow and AutoFlow.
//
//   - Request and response processors for different stages of LLM interaction,
//     including basic processing, instruction management, content optimization,
//     natural language planning, and code execution.
//
//   - Context management for maintaining state during flow execution.
//
// The package is designed to be extensible, allowing for custom flows
// and processors to be implemented for specific application needs.
package flow