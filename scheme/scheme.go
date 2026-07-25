// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package scheme defines the contract between gen-corim and the attestation
// schemes it knows how to read evidence for.
package scheme

import (
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/veraison/corim/comid"
)

// Payload is the set of CoMIDs destined for a single CoRIM of a single profile.
// Label names the generated file where a scheme produces more than one CoRIM.
type Payload struct {
	Profile string
	Label   string
	Comids  []*comid.Comid
}

// ComidBuilder mints CoMIDs that carry the metadata read from the CoMID
// template and have the extensions of the requested profile registered.
type ComidBuilder interface {
	NewComid(profileURI string) (*comid.Comid, error)
}

// Scheme turns the evidence of one attestation scheme into CoRIM payloads. Each
// implementation is exposed as a gen-corim sub-command.
type Scheme interface {
	// Use is the cobra usage line, e.g. "psa <token-file>", whose first word
	// is the sub-command name.
	Use() string
	Short() string
	Long() string
	Args() cobra.PositionalArgs
	// AddFlags binds the scheme-specific flags to the receiver, not to
	// package-level state.
	AddFlags(flags *pflag.FlagSet)
	// Generate reads the evidence named by args. CoMIDs must come from b, so
	// that they carry the template metadata and the profile extensions.
	Generate(fs afero.Fs, b ComidBuilder, args []string) ([]Payload, error)
}

// Factory returns a new Scheme with its own flag state, so that every command
// built has independent flags.
type Factory func() Scheme
