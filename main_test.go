package main

import (
	"testing"
)

func TestMainPackageBasics(t *testing.T) {
	// Test that projectID is set in test environment
	if projectID != "test-project" {
		t.Errorf("Expected projectID to be 'test-project' in test env, got '%s'", projectID)
	}
}