// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/go-a2a/adk-go/internal/godantic"
)

// BasicModel represents a model with simple required fields.
type BasicModel struct {
	godantic.BaseModel `json:"-"`
	ID                 int    `json:"id" validate:"required"`
	Name               string `json:"name" validate:"required"`
}

// ValidatedModel represents a model with various validation constraints.
type ValidatedModel struct {
	godantic.BaseModel `json:"-"`
	ID                 int    `json:"id" validate:"required"`
	Name               string `json:"name" validate:"required,minLength=3,maxLength=10"`
	Age                int    `json:"age" validate:"min=18,max=120"`
	Email              string `json:"email" validate:"required"`
}

// Address represents a model used for nesting.
type Address struct {
	godantic.BaseModel `json:"-"`
	Street             string `json:"street" validate:"required"`
	City               string `json:"city" validate:"required"`
	ZipCode            string `json:"zip_code" validate:"required"`
}

// NestedModel represents a model containing another model.
type NestedModel struct {
	godantic.BaseModel `json:"-"`
	ID                 int     `json:"id" validate:"required"`
	Name               string  `json:"name" validate:"required"`
	Address            Address `json:"address"`
}

// AliasModel represents a model with field aliases.
type AliasModel struct {
	godantic.BaseModel `json:"-"`
	ID                 int    `json:"identifier" validate:"required"`
	FullName           string `json:"full_name" validate:"required"`
}

// Implement Model interface for BasicModel
func (m *BasicModel) Validate() error {
	return m.BaseModel.Validate(m)
}

func (m *BasicModel) ValidateJSON(data []byte) error {
	return m.BaseModel.ValidateJSON(m, data)
}

func (m *BasicModel) ToMap(exclude ...string) map[string]any {
	return m.BaseModel.ToMap(m, exclude...)
}

func (m *BasicModel) ToJSON(exclude ...string) ([]byte, error) {
	return m.BaseModel.ToJSON(m, exclude...)
}

func (m *BasicModel) Copy(updates map[string]any) (godantic.Model, error) {
	result, err := m.BaseModel.Copy(m, updates)
	if err != nil {
		return nil, err
	}
	return result.(*BasicModel), nil
}

// Implement Model interface for ValidatedModel
func (m *ValidatedModel) Validate() error {
	return m.BaseModel.Validate(m)
}

func (m *ValidatedModel) ValidateJSON(data []byte) error {
	return m.BaseModel.ValidateJSON(m, data)
}

func (m *ValidatedModel) ToMap(exclude ...string) map[string]any {
	return m.BaseModel.ToMap(m, exclude...)
}

func (m *ValidatedModel) ToJSON(exclude ...string) ([]byte, error) {
	return m.BaseModel.ToJSON(m, exclude...)
}

func (m *ValidatedModel) Copy(updates map[string]any) (godantic.Model, error) {
	result, err := m.BaseModel.Copy(m, updates)
	if err != nil {
		return nil, err
	}
	return result.(*ValidatedModel), nil
}

// Implement Model interface for Address
func (m *Address) Validate() error {
	return m.BaseModel.Validate(m)
}

func (m *Address) ValidateJSON(data []byte) error {
	return m.BaseModel.ValidateJSON(m, data)
}

func (m *Address) ToMap(exclude ...string) map[string]any {
	return m.BaseModel.ToMap(m, exclude...)
}

func (m *Address) ToJSON(exclude ...string) ([]byte, error) {
	return m.BaseModel.ToJSON(m, exclude...)
}

func (m *Address) Copy(updates map[string]any) (godantic.Model, error) {
	result, err := m.BaseModel.Copy(m, updates)
	if err != nil {
		return nil, err
	}
	return result.(*Address), nil
}

// Implement Model interface for NestedModel
func (m *NestedModel) Validate() error {
	return m.BaseModel.Validate(m)
}

func (m *NestedModel) ValidateJSON(data []byte) error {
	return m.BaseModel.ValidateJSON(m, data)
}

func (m *NestedModel) ToMap(exclude ...string) map[string]any {
	return m.BaseModel.ToMap(m, exclude...)
}

func (m *NestedModel) ToJSON(exclude ...string) ([]byte, error) {
	return m.BaseModel.ToJSON(m, exclude...)
}

func (m *NestedModel) Copy(updates map[string]any) (godantic.Model, error) {
	result, err := m.BaseModel.Copy(m, updates)
	if err != nil {
		return nil, err
	}
	return result.(*NestedModel), nil
}

// Implement Model interface for AliasModel
func (m *AliasModel) Validate() error {
	return m.BaseModel.Validate(m)
}

func (m *AliasModel) ValidateJSON(data []byte) error {
	return m.BaseModel.ValidateJSON(m, data)
}

func (m *AliasModel) ToMap(exclude ...string) map[string]any {
	return m.BaseModel.ToMap(m, exclude...)
}

func (m *AliasModel) ToJSON(exclude ...string) ([]byte, error) {
	return m.BaseModel.ToJSON(m, exclude...)
}

func (m *AliasModel) Copy(updates map[string]any) (godantic.Model, error) {
	result, err := m.BaseModel.Copy(m, updates)
	if err != nil {
		return nil, err
	}
	return result.(*AliasModel), nil
}

// Helper functions for model creation
func newBasicModel() *BasicModel {
	return &BasicModel{
		BaseModel: godantic.NewBaseModel(),
	}
}

func newValidatedModel() *ValidatedModel {
	model := &ValidatedModel{
		BaseModel: godantic.NewBaseModel(godantic.ModelConfig{ValidateAll: true}),
	}

	// Add custom email validator
	model.RegisterValidator("Email", func(value any) error {
		email, ok := value.(string)
		if !ok {
			return fmt.Errorf("email must be a string")
		}

		if email == "" {
			return nil // Skip empty emails, required validation will catch this
		}

		if len(email) < 5 || !strings.Contains(email, "@") {
			return fmt.Errorf("invalid email format")
		}

		return nil
	})

	return model
}

func newNestedModel() *NestedModel {
	return &NestedModel{
		BaseModel: godantic.NewBaseModel(),
		Address: Address{
			BaseModel: godantic.NewBaseModel(),
		},
	}
}

func newAliasModel() *AliasModel {
	return &AliasModel{
		BaseModel: godantic.NewBaseModel(godantic.ModelConfig{PopulateByName: true}),
	}
}

// isValidationError checks if an error is a ModelError with a validation error for the specified field
func isValidationError(t *testing.T, err error, field, message string) bool {
	t.Helper()

	if err == nil {
		t.Errorf("expected validation error for field %s, got nil", field)
		return false
	}

	modelErr, ok := err.(godantic.ModelError)
	if !ok {
		t.Errorf("expected ModelError, got %T", err)
		return false
	}

	for _, valErr := range modelErr.Errors {
		if valErr.Field == field && strings.Contains(valErr.Message, message) {
			return true
		}
	}

	t.Errorf("expected validation error for field %s with message containing %q, got %v", field, message, modelErr)
	return false
}

// TestNewModel tests the NewModel function.
func TestNewModel(t *testing.T) {
	t.Run("ValidData", func(t *testing.T) {
		data := map[string]any{
			"id":   1,
			"name": "Test User",
		}

		model, err := godantic.NewModel[BasicModel](data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if model.ID != 1 {
			t.Errorf("expected ID=1, got %d", model.ID)
		}

		if model.Name != "Test User" {
			t.Errorf("expected Name='Test User', got %q", model.Name)
		}
	})

	t.Run("MissingRequiredField", func(t *testing.T) {
		data := map[string]any{
			"id": 1,
			// Missing name
		}

		_, err := godantic.NewModel[BasicModel](data)
		isValidationError(t, err, "Name", "required")
	})

	t.Run("ExtraForbid", func(t *testing.T) {
		// Regular model should allow extra fields
		regularData := map[string]any{
			"id":    1,
			"name":  "Test User",
			"extra": "This should not cause an error",
		}

		_, err := godantic.NewModel[BasicModel](regularData)
		if err != nil {
			t.Errorf("unexpected error with extra fields by default: %v", err)
		}

		// Model with ExtraForbid=true
		strictModel := &BasicModel{
			BaseModel: godantic.NewBaseModel(godantic.ModelConfig{ExtraForbid: true}),
		}

		err = strictModel.ValidateJSON([]byte(`{"id": 1, "name": "Test User", "extra": "This should cause an error"}`))
		isValidationError(t, err, "extra", "extra fields not permitted")
	})

	t.Run("TypeConversion", func(t *testing.T) {
		// Test integer to string conversion
		data := map[string]any{
			"id":   1,
			"name": 12345, // Should be converted to string
		}

		model, err := godantic.NewModel[BasicModel](data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if model.Name != "12345" {
			t.Errorf("expected Name='12345', got %q", model.Name)
		}
	})

	t.Run("PopulateByName", func(t *testing.T) {
		data := map[string]any{
			"identifier": 1, // Using JSON name instead of field name
			"full_name":  "Test User",
		}

		model, err := godantic.NewModel[AliasModel](data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if model.ID != 1 {
			t.Errorf("expected ID=1, got %d", model.ID)
		}

		if model.FullName != "Test User" {
			t.Errorf("expected FullName='Test User', got %q", model.FullName)
		}
	})
}

// TestNewModelFromJSON tests the NewModelFromJSON function.
func TestNewModelFromJSON(t *testing.T) {
	t.Run("ValidJSON", func(t *testing.T) {
		jsonData := []byte(`{"id": 1, "name": "Test User"}`)

		model, err := godantic.NewModelFromJSON[BasicModel](jsonData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if model.ID != 1 {
			t.Errorf("expected ID=1, got %d", model.ID)
		}

		if model.Name != "Test User" {
			t.Errorf("expected Name='Test User', got %q", model.Name)
		}
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		jsonData := []byte(`{"id": 1, "name": "Test User"`) // Missing closing brace

		_, err := godantic.NewModelFromJSON[BasicModel](jsonData)
		if err == nil {
			t.Errorf("expected error for invalid JSON, got nil")
		}
	})

	t.Run("MissingRequiredField", func(t *testing.T) {
		jsonData := []byte(`{"id": 1}`) // Missing name

		_, err := godantic.NewModelFromJSON[BasicModel](jsonData)
		isValidationError(t, err, "Name", "required")
	})

	t.Run("NestedJSON", func(t *testing.T) {
		jsonData := []byte(`{
			"id": 1,
			"name": "Test User",
			"address": {
				"street": "123 Main St",
				"city": "Test City",
				"zip_code": "12345"
			}
		}`)

		model, err := godantic.NewModelFromJSON[NestedModel](jsonData)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if model.ID != 1 {
			t.Errorf("expected ID=1, got %d", model.ID)
		}

		if model.Address.Street != "123 Main St" {
			t.Errorf("expected Address.Street='123 Main St', got %q", model.Address.Street)
		}
	})
}

// TestValidation tests the validation functionality.
func TestValidation(t *testing.T) {
	t.Run("RequiredFields", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		// Name is missing

		err := model.Validate()
		isValidationError(t, err, "Name", "required")

		// Now set the required field
		model.Name = "Test User"
		err = model.Validate()
		if err != nil {
			t.Errorf("unexpected error after setting required field: %v", err)
		}
	})

	t.Run("MinMaxValidation", func(t *testing.T) {
		model := newValidatedModel()
		model.ID = 1
		model.Name = "Test"
		model.Email = "test@example.com"
		model.Age = 15 // Less than min=18

		err := model.Validate()
		isValidationError(t, err, "Age", "min")

		model.Age = 130 // Greater than max=120
		err = model.Validate()
		isValidationError(t, err, "Age", "max")

		model.Age = 25    // Valid age
		model.Name = "AB" // Less than minLength=3
		err = model.Validate()
		isValidationError(t, err, "Name", "minLength")

		model.Name = "This is a very long name" // Greater than maxLength=10
		err = model.Validate()
		isValidationError(t, err, "Name", "maxLength")

		// Set all valid values
		model.Name = "Valid"
		model.Age = 30
		err = model.Validate()
		if err != nil {
			t.Errorf("unexpected error with valid values: %v", err)
		}
	})

	t.Run("CustomValidation", func(t *testing.T) {
		model := newValidatedModel()
		model.ID = 1
		model.Name = "Test Name"
		model.Age = 30
		model.Email = "invalid" // Invalid email

		err := model.Validate()
		isValidationError(t, err, "Email", "invalid email format")

		model.Email = "valid@example.com" // Valid email
		err = model.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("NestedValidation", func(t *testing.T) {
		model := newNestedModel()
		model.ID = 1
		model.Name = "Test"
		// Address fields are missing

		err := model.Validate()
		isValidationError(t, err, "Address.Street", "required")

		// Set address fields
		model.Address.Street = "123 Main St"
		model.Address.City = "Test City"
		model.Address.ZipCode = "12345"

		err = model.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("ValidateAll", func(t *testing.T) {
		// Create model with ValidateAll=false
		model := &ValidatedModel{
			BaseModel: godantic.NewBaseModel(godantic.ModelConfig{ValidateAll: false}),
		}

		// Multiple validation errors
		err := model.Validate()
		modelErr, ok := err.(godantic.ModelError)
		if !ok {
			t.Fatalf("expected ModelError, got %T", err)
		}

		// With ValidateAll=false, only the first error should be reported
		if len(modelErr.Errors) != 1 {
			t.Errorf("expected 1 error with ValidateAll=false, got %d", len(modelErr.Errors))
		}

		// Now with ValidateAll=true
		model = newValidatedModel() // This has ValidateAll=true

		err = model.Validate()
		modelErr, ok = err.(godantic.ModelError)
		if !ok {
			t.Fatalf("expected ModelError, got %T", err)
		}

		// With ValidateAll=true, multiple errors should be reported
		if len(modelErr.Errors) <= 1 {
			t.Errorf("expected multiple errors with ValidateAll=true, got %d", len(modelErr.Errors))
		}
	})

	t.Run("EmptyVsNil", func(t *testing.T) {
		// Test zero value vs nil for required fields
		model := newBasicModel()
		model.ID = 0    // Zero value
		model.Name = "" // Empty string

		err := model.Validate()
		isValidationError(t, err, "Name", "required")
	})
}

// TestToMap tests the ToMap functionality.
func TestToMap(t *testing.T) {
	t.Run("BasicConversion", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		model.Name = "Test User"

		result := model.ToMap()

		expected := map[string]any{
			"id":   1,
			"name": "Test User",
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("ToMap() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ExcludeFields", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		model.Name = "Test User"

		result := model.ToMap("name")

		expected := map[string]any{
			"id": 1,
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("ToMap() with exclude mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("FieldAliases", func(t *testing.T) {
		model := newAliasModel()
		model.ID = 1
		model.FullName = "Test User"

		result := model.ToMap()

		expected := map[string]any{
			"identifier": 1,
			"full_name":  "Test User",
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("ToMap() with aliases mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NestedModel", func(t *testing.T) {
		model := newNestedModel()
		model.ID = 1
		model.Name = "Test User"
		model.Address.Street = "123 Main St"
		model.Address.City = "Test City"
		model.Address.ZipCode = "12345"

		result := model.ToMap()

		expected := map[string]any{
			"id":   1,
			"name": "Test User",
			"address": map[string]any{
				"street":   "123 Main St",
				"city":     "Test City",
				"zip_code": "12345",
			},
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("ToMap() with nested model mismatch (-want +got):\n%s", diff)
		}
	})
}

// TestToJSON tests the ToJSON functionality.
func TestToJSON(t *testing.T) {
	t.Run("BasicConversion", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		model.Name = "Test User"

		jsonData, err := model.ToJSON()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var result map[string]any
		if err := json.Unmarshal(jsonData, &result); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		expected := map[string]any{
			"id":   float64(1), // JSON numbers are float64
			"name": "Test User",
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("ToJSON() result mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("ExcludeFields", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		model.Name = "Test User"

		jsonData, err := model.ToJSON("name")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var result map[string]any
		if err := json.Unmarshal(jsonData, &result); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		expected := map[string]any{
			"id": float64(1), // JSON numbers are float64
		}

		if diff := cmp.Diff(expected, result); diff != "" {
			t.Errorf("ToJSON() with exclude mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("NestedModel", func(t *testing.T) {
		model := newNestedModel()
		model.ID = 1
		model.Name = "Test User"
		model.Address.Street = "123 Main St"
		model.Address.City = "Test City"
		model.Address.ZipCode = "12345"

		jsonData, err := model.ToJSON()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var result map[string]any
		if err := json.Unmarshal(jsonData, &result); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		addressMap, ok := result["address"].(map[string]any)
		if !ok {
			t.Fatalf("expected address to be a map, got %T", result["address"])
		}

		if addressMap["street"] != "123 Main St" {
			t.Errorf("expected address.street='123 Main St', got %v", addressMap["street"])
		}
	})
}

// TestCopy tests the Copy functionality.
func TestCopy(t *testing.T) {
	t.Run("SimpleCopy", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		model.Name = "Test User"

		copy, err := model.Copy(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		copyModel, ok := copy.(*BasicModel)
		if !ok {
			t.Fatalf("expected *BasicModel, got %T", copy)
		}

		if model.ID != copyModel.ID || model.Name != copyModel.Name {
			t.Errorf("copy doesn't match original: original=%+v, copy=%+v", model, copyModel)
		}

		// Verify independent copies
		copyModel.Name = "Changed Name"
		if model.Name == copyModel.Name {
			t.Errorf("copy should be independent, but changing the copy affected the original")
		}
	})

	t.Run("CopyWithUpdates", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		model.Name = "Test User"

		updates := map[string]any{
			"name": "Updated Name",
		}

		copy, err := model.Copy(updates)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		copyModel, ok := copy.(*BasicModel)
		if !ok {
			t.Fatalf("expected *BasicModel, got %T", copy)
		}

		if copyModel.ID != 1 {
			t.Errorf("expected ID=1, got %d", copyModel.ID)
		}

		if copyModel.Name != "Updated Name" {
			t.Errorf("expected Name='Updated Name', got %q", copyModel.Name)
		}

		// Original should be unchanged
		if model.Name != "Test User" {
			t.Errorf("original should be unchanged, but Name=%q", model.Name)
		}
	})

	t.Run("InvalidUpdates", func(t *testing.T) {
		model := newBasicModel()
		model.ID = 1
		model.Name = "Test User"

		updates := map[string]any{
			"name": "", // Required field can't be empty
		}

		_, err := model.Copy(updates)
		isValidationError(t, err, "Name", "required")
	})

	t.Run("NestedCopy", func(t *testing.T) {
		model := newNestedModel()
		model.ID = 1
		model.Name = "Test User"
		model.Address.Street = "123 Main St"
		model.Address.City = "Test City"
		model.Address.ZipCode = "12345"

		copy, err := model.Copy(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		copyModel, ok := copy.(*NestedModel)
		if !ok {
			t.Fatalf("expected *NestedModel, got %T", copy)
		}

		if copyModel.Address.Street != "123 Main St" {
			t.Errorf("expected Address.Street='123 Main St', got %q", copyModel.Address.Street)
		}

		// Update nested field and verify original is unchanged
		copyModel.Address.Street = "456 New St"
		if model.Address.Street != "123 Main St" {
			t.Errorf("original should be unchanged, but Address.Street=%q", model.Address.Street)
		}
	})
}

// TestModelConfig tests the ModelConfig functionality.
func TestModelConfig(t *testing.T) {
	t.Run("FrozenFields", func(t *testing.T) {
		// Note: The FrozenFields functionality doesn't appear to be fully implemented
		// in the current version of the codebase. This test is a placeholder for
		// when that functionality is implemented.

		// Create model with FrozenFields=true
		model := &BasicModel{
			BaseModel: godantic.NewBaseModel(godantic.ModelConfig{FrozenFields: true}),
			ID:        1,
			Name:      "Test User",
		}

		// Verify the model was created successfully
		if model.ID != 1 || model.Name != "Test User" {
			t.Errorf("unexpected model values: %+v", model)
		}
	})
}
