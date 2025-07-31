//go:build !oomtest
// +build !oomtest

package oom

// setupOOMTestHandler is a no-op when the oomtest build tag is not present
func setupOOMTestHandler() {
	// No-op - OOM testing is not compiled in
}
