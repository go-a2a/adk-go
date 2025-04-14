// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

// Package llmflow provides implementations of flows for interacting with
// large language models (LLMs).
//
// The package offers different flow types for various LLM interaction patterns:
//
//   - BaseLLMFlow: A base implementation for LLM-based flows that handles
//     the core flow execution logic, including request preprocessing,
//     LLM interaction, and response postprocessing.
//
//   - SingleFlow: A simple flow for single-agent interactions with no sub-agents,
//     configured with standard processors for basic functionality.
//
//   - AutoFlow: An extension of SingleFlow that adds agent transfer capabilities,
//     allowing for more complex multi-agent interactions.
//
// The flows in this package are designed to be flexible and composable,
// allowing for customization through processor selection and configuration.
// They handle both synchronous and streaming LLM interactions, with support
// for function calling and context management.
package llmflow
