// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package cca generates CCA endorsements from a CCA attestation token.
package cca

import (
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/veraison/ccatoken"
	"github.com/veraison/gen-corim/scheme"
)

// Parts of a CCA token that can be turned into endorsements. The platform and
// the realm are described by two different CoRIM profiles, so each is a CoRIM
// of its own.
const (
	PartPlatform = "platform"
	PartRealm    = "realm"
	PartBoth     = "both"
)

// Scheme generates CoRIMs from a CCA attestation token.
type Scheme struct {
	part string
}

// New returns a CCA scheme with its own flag state.
func New() scheme.Scheme { return &Scheme{} }

func (o *Scheme) Use() string { return "cca <token-file>" }

func (o *Scheme) Short() string { return "generate CCA endorsements from a CCA token" }

func (o *Scheme) Long() string {
	return `Generate CCA endorsements from a CCA attestation token.

A CCA token describes two target environments, the platform and the realm, and
each has its own CoRIM profile. They are therefore emitted as two CoRIMs; use
--part to generate only one of them.

	gen-corim cca token.cbor --template-dir=templates
	gen-corim cca token.cbor --template-dir=templates --part=platform

The software components of the platform token become the reference values of
the platform CoRIM, along with its configuration.
`
}

func (o *Scheme) Args() cobra.PositionalArgs { return cobra.ExactArgs(1) }

func (o *Scheme) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.part, "part", PartBoth,
		"which part of the token to generate endorsements for: platform, realm or both")
}

// Generate decodes the token and turns its claims into one CoRIM payload per
// requested part.
func (o *Scheme) Generate(
	fs afero.Fs, b scheme.ComidBuilder, args []string,
) ([]scheme.Payload, error) {
	if err := o.validFlags(); err != nil {
		return nil, err
	}

	token, err := afero.ReadFile(fs, args[0])
	if err != nil {
		return nil, fmt.Errorf("error loading token from %s: %w", args[0], err)
	}

	evidence, err := ccatoken.DecodeAndValidateEvidenceFromCBOR(token)
	if err != nil {
		return nil, fmt.Errorf("error decoding token from %s: %w", args[0], err)
	}

	var payloads []scheme.Payload

	if o.part == PartPlatform || o.part == PartBoth {
		payload, err := platformPayload(b, evidence)
		if err != nil {
			return nil, err
		}

		payloads = append(payloads, *payload)
	}

	return payloads, nil
}

func (o *Scheme) validFlags() error {
	switch o.part {
	case PartPlatform, PartRealm, PartBoth:
		return nil
	default:
		return fmt.Errorf("unsupported part %q, want %q, %q or %q",
			o.part, PartPlatform, PartRealm, PartBoth)
	}
}
