// Copyright 2025 The adk-go Authors
// SPDX-License-Identifier: Apache-2.0

package ptr_test

import (
	"fmt"
	"testing"

	"github.com/go-a2a/adk-go/pkg/utils/ptr"
)

func TestRef(t *testing.T) {
	type T int

	val := T(0)
	pointer := ptr.To(val)
	if *pointer != val {
		t.Errorf("expected %d, got %d", val, *pointer)
	}

	val = T(1)
	pointer = ptr.To(val)
	if *pointer != val {
		t.Errorf("expected %d, got %d", val, *pointer)
	}
}

func TestDeref(t *testing.T) {
	type T int

	var val, def T = 1, 0

	out := ptr.Deref(&val, def)
	if out != val {
		t.Errorf("expected %d, got %d", val, out)
	}

	out = ptr.Deref(nil, def)
	if out != def {
		t.Errorf("expected %d, got %d", def, out)
	}
}

func TestEqual(t *testing.T) {
	type T int

	if !ptr.Equal[T](nil, nil) {
		t.Errorf("expected true (nil == nil)")
	}
	if !ptr.Equal(ptr.To(T(123)), ptr.To(T(123))) {
		t.Errorf("expected true (val == val)")
	}
	if ptr.Equal(nil, ptr.To(T(123))) {
		t.Errorf("expected false (nil != val)")
	}
	if ptr.Equal(ptr.To(T(123)), nil) {
		t.Errorf("expected false (val != nil)")
	}
	if ptr.Equal(ptr.To(T(123)), ptr.To(T(456))) {
		t.Errorf("expected false (val != val)")
	}
}

func TestAllPtrFieldsNil(t *testing.T) {
	testCases := []struct {
		obj      any
		expected bool
	}{
		{struct{}{}, true},
		{struct{ Foo int }{12345}, true},
		{&struct{ Foo int }{12345}, true},
		{struct{ Foo *int }{nil}, true},
		{&struct{ Foo *int }{nil}, true},
		{struct {
			Foo int
			Bar *int
		}{12345, nil}, true},
		{&struct {
			Foo int
			Bar *int
		}{12345, nil}, true},
		{struct {
			Foo *int
			Bar *int
		}{nil, nil}, true},
		{&struct {
			Foo *int
			Bar *int
		}{nil, nil}, true},
		{struct{ Foo *int }{new(int)}, false},
		{&struct{ Foo *int }{new(int)}, false},
		{struct {
			Foo *int
			Bar *int
		}{nil, new(int)}, false},
		{&struct {
			Foo *int
			Bar *int
		}{nil, new(int)}, false},
		{(*struct{})(nil), true},
	}
	for i, tc := range testCases {
		name := fmt.Sprintf("case[%d]", i)
		t.Run(name, func(t *testing.T) {
			if actual := ptr.AllPtrFieldsNil(tc.obj); actual != tc.expected {
				t.Errorf("%s: expected %t, got %t", name, tc.expected, actual)
			}
		})
	}
}
