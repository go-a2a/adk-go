// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

// Package processors provides implementations of request and response processors
// for LLM flows.
//
// Request processors handle preprocessing of LLM requests, including:
//
//   - BasicRequestProcessor: Handles basic configuration of LLM requests.
//
//   - InstructionsRequestProcessor: Adds system instructions to LLM requests.
//
//   - IdentityRequestProcessor: Adds agent identity information to requests.
//
//   - ContentsRequestProcessor: Optimizes content for LLM consumption.
//
//   - NLPlanningRequestProcessor: Adds natural language planning capabilities.
//
//   - CodeExecutionRequestProcessor: Configures code execution for requests.
//
//   - AgentTransferRequestProcessor: Handles agent transfers between flows.
//
// Response processors handle postprocessing of LLM responses, including:
//
//   - NLPlanningResponseProcessor: Processes planning-related content in responses.
//
//   - CodeExecutionResponseProcessor: Handles code execution in responses.
//
// Each processor focuses on a specific aspect of LLM interaction, allowing
// for modular and composable flow construction. Processors can be added
// to flows in different orders to achieve various behaviors and capabilities.
package processors
