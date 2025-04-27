// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic_test

import (
	"fmt"
	"regexp"

	"github.com/go-a2a/adk-go/internal/godantic"
)

// User demonstrates a model with validation.
type User struct {
	godantic.BaseModel `json:"-"`
	ID                 int    `json:"id" validate:"required"`
	Name               string `json:"name" validate:"required,minLength=2"`
	Email              string `json:"email" validate:"required"`
	Age                int    `json:"age" validate:"min=0,max=120"`
}

// NewUser creates a new User with configured validators.
func NewUser() *User {
	user := &User{
		BaseModel: godantic.NewBaseModel(godantic.ModelConfig{ValidateAll: true}),
	}
	user.RegisterValidator("Email", validateEmail)
	return user
}

// Validate implements the Model interface.
func (u *User) Validate() error {
	return u.BaseModel.Validate(u)
}

// ValidateJSON implements the Model interface.
func (u *User) ValidateJSON(data []byte) error {
	return u.BaseModel.ValidateJSON(u, data)
}

// ToMap implements the Model interface.
func (u *User) ToMap(exclude ...string) map[string]any {
	return u.BaseModel.ToMap(u, exclude...)
}

// ToJSON implements the Model interface.
func (u *User) ToJSON(exclude ...string) ([]byte, error) {
	return u.BaseModel.ToJSON(u, exclude...)
}

// Copy implements the Model interface.
func (u *User) Copy(updates map[string]any) (godantic.Model, error) {
	result, err := u.BaseModel.Copy(u, updates)
	if err != nil {
		return nil, err
	}
	return result.(*User), nil
}

// Email validator function.
func validateEmail(value any) error {
	email, ok := value.(string)
	if !ok {
		return fmt.Errorf("email must be a string")
	}

	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(pattern, email)
	if err != nil {
		return fmt.Errorf("error validating email: %w", err)
	}

	if !matched {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

func Example() {
	// Create a model from map
	userData := map[string]any{
		"id":    1,
		"name":  "John Doe",
		"email": "john@example.com",
		"age":   30,
	}

	user, err := godantic.NewModel[User](userData)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Create from JSON
	jsonData := []byte(`{"id": 2, "name": "Jane Doe", "email": "jane@example.com", "age": 28}`)

	user2, err := godantic.NewModelFromJSON[User](jsonData)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Validation error example
	invalidData := map[string]any{
		"id":    3,
		"name":  "Bob",
		"email": "invalid-email",
		"age":   150,
	}

	_, err = godantic.NewModel[User](invalidData)
	if err != nil {
		fmt.Println("Validation error:", err)
	}

	// Convert to map
	userMap := user.ToMap()
	fmt.Printf("User as map: %+v\n", userMap)

	// Copy with updates
	updatedUser, err := user.Copy(map[string]any{"age": 31})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	updatedUserMap := updatedUser.ToMap()
	fmt.Printf("Updated user: %+v\n", updatedUserMap)

	// Convert second user to JSON
	userJSON, err := user2.ToJSON()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("User2 as JSON: %s\n", userJSON)
}
