//go:build mage
// +build mage

package main

import (
	//mage:import bpf
	_ "github.com/parca-dev/parca-agent/build/bpf"

	//mage:import deploy
	_ "github.com/parca-dev/parca-agent/build/deploy"

	//mage:import cgo
	_ "github.com/parca-dev/parca-agent/build/cgo"
)
