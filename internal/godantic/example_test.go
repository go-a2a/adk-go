// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic_test

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/go-a2a/adk-go/internal/godantic"
)

// User demonstrates a model similar to a Pydantic BaseModel.
type User struct {
	ID       int    `json:"id" godantic:"required"`
	Name     string `json:"name" godantic:"required"`
	Email    string `json:"email" godantic:"required"`
	Age      int    `json:"age" godantic:"min=0,max=120"`
	Password string `json:"password,omitempty"`
}

func Example() {
	// Create a new model with validation rules
	user := User{
		ID:    1,
		Name:  "John Doe",
		Email: "john@example.com",
		Age:   30,
	}

	// Create and validate the model
	model, err := godantic.New(user)
	if err != nil {
		log.Fatalf("Validation error: %v", err)
	}

	// Dump the model to a map
	dataMap := model.Dump()
	fmt.Printf("User data: %v\n", dataMap)

	// Dump the model to JSON
	jsonData, err := model.DumpJSON()
	if err != nil {
		log.Fatalf("JSON error: %v", err)
	}
	fmt.Printf("User JSON: %s\n", jsonData)

	// Validate JSON data against the model
	newUserJSON := []byte(`{"id": 2, "name": "Jane Doe", "email": "jane@example.com", "age": 25}`)
	err = model.ValidateJSON(newUserJSON)
	if err != nil {
		log.Fatalf("JSON validation error: %v", err)
	}
	fmt.Println("JSON data validated successfully")

	// Generate JSON schema
	schema := model.JSONSchema()
	schemaJSON, _ := json.MarshalIndent(schema, "", "  ")
	fmt.Printf("JSON schema:\n%s\n", schemaJSON)
}

func ExampleStrictMode() {
	// Create a model with strict validation
	user := User{
		ID:    1,
		Name:  "John Doe",
		Email: "john@example.com",
		Age:   30,
	}

	// Use strict mode
	model, err := godantic.New(user, godantic.StrictMode())
	if err != nil {
		log.Fatalf("Validation error: %v", err)
	}

	fmt.Printf("Created model with strict validation: %v\n", model != nil)
}

func ExampleEmailValidator() {
	// Create a custom field with email validation
	type ContactInfo struct {
		Email string `json:"email"`
	}

	contact := ContactInfo{
		Email: "invalid-email", // Invalid email format
	}

	// Define custom model with email validator
	model, err := godantic.New(ContactInfo{})
	if err != nil {
		log.Fatalf("Schema error: %v", err)
	}

	// Validate the data (should fail)
	err = model.Validate(contact)
	if err != nil {
		fmt.Printf("Validation failed as expected: %v\n", err)
	}

	// Fix the email
	contact.Email = "valid@example.com"

	// Validate again (should pass)
	err = model.Validate(contact)
	if err != nil {
		log.Fatalf("Validation error: %v", err)
	}

	fmt.Println("Email validation passed")
}
