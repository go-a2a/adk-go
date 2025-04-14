// Copyright 2025 The go-a2a Authors
// Licensed under the Apache License, Version 2.0

package planner

import (
	"fmt"
	"sync"
)

// Registry provides a central location for registering and retrieving planners.
type Registry struct {
	mu       sync.RWMutex
	planners map[string]Planner
}

// NewRegistry creates a new planner registry.
func NewRegistry() *Registry {
	registry := &Registry{
		planners: make(map[string]Planner),
	}

	// Register default planners
	registry.Register("built_in", NewBuiltInPlanner(nil))
	registry.Register("plan_re_act", NewPlanReActPlanner())

	return registry
}

// Register adds a planner to the registry.
func (r *Registry) Register(name string, planner Planner) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.planners[name] = planner
}

// Get retrieves a planner from the registry.
func (r *Registry) Get(name string) (Planner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	planner, ok := r.planners[name]
	if !ok {
		return nil, fmt.Errorf("planner not found: %s", name)
	}

	return planner, nil
}

// List returns all registered planner names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.planners))
	for name := range r.planners {
		names = append(names, name)
	}

	return names
}
