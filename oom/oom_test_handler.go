//go:build oomtest
// +build oomtest

package oom

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// memoryBombs holds allocated memory to prevent GC from freeing it
var memoryBombs [][]byte

// oomOnce ensures the OOM trigger only runs once
var oomOnce sync.Once

// setupOOMTestHandler sets up a signal handler that triggers massive memory allocation
// when SIGUSR2 is received.
func setupOOMTestHandler() {
	log.Warn("OOM testing mode enabled - SIGUSR2 will trigger memory allocation bomb")

	// Create a channel to receive SIGUSR2 signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR2)

	go func() {
		for range sigChan {
			// do once to avoid multiple triggers
			oomOnce.Do(func() {
				log.Warn("SIGUSR2 received - triggering OOM by allocating memory aggressively")
				// Start the memory allocation bomb
				triggerOOM()
			})
		}
	}()
}

// triggerOOM allocates memory aggressively to force an OOM condition
func triggerOOM() {
	// Start allocating memory in chunks
	chunkSize := 1 * 1024 * 1024
	allocations := 0

	log.Info("Starting memory allocation bomb...")

	// Allocate memory until we get killed
	for { // 10MB chunks
		// Allocate a chunk
		chunk := make([]byte, chunkSize)

		// Fill it with data to ensure it's actually allocated
		for i := range chunk {
			chunk[i] = byte(i % 256)
		}

		// Keep reference to prevent GC
		memoryBombs = append(memoryBombs, chunk)
		allocations++

		// Log progress every 10 allocations
		if allocations%10 == 0 {
			totalMB := (allocations * chunkSize) / (1024 * 1024)
			log.Infof("Allocated %d chunks, total: %d MB", allocations, totalMB)
		}
	}
}

// init is called automatically when the package is imported
func init() {
	setupOOMTestHandler()
}
