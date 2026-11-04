//go:build ignore

// Input to `go tool cgo -godefs` (go generate): the schema is defined once,
// in parcagpu's src/parcagpu_ctl.h (copied here), and types_gen.go is
// generated from it.

package control

/*
#include "parcagpu_ctl.h"
*/
import "C"

type ctlConfig C.struct_parcagpu_ctl_config
type ctlDevice C.struct_parcagpu_ctl_device
type ctlState C.struct_parcagpu_ctl_state

const (
	schemaVersion = C.PARCAGPU_CTL_SCHEMA_VERSION
	maxDevices    = C.PARCAGPU_CTL_MAX_DEVICES

	pcOff         = C.PARCAGPU_PC_OFF
	pcOn          = C.PARCAGPU_PC_ON
	pcUnavailable = C.PARCAGPU_PC_UNAVAILABLE
)
