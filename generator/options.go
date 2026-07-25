// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"errors"
	"fmt"
)

// Output formats accepted by the --format flag.
const (
	FormatCBOR = "cbor"
	FormatJSON = "json"
)

// errSignedJSON is reported both by Valid, which is where a caller meets it,
// and by the signing itself, which cannot carry the request out either way.
var errSignedJSON = errors.New("a signed CoRIM cannot be serialized as JSON")

// Options carries the settings that are common to every attestation scheme.
type Options struct {
	// TemplateDir is the directory holding the CoRIM and CoMID templates.
	TemplateDir string
	// OutputDir is the directory the generated CoRIMs are written to.
	OutputDir string
	// CorimFile, when set, is the whole path of the generated CoRIM, so
	// OutputDir does not apply. It may only be used when the run produces
	// exactly one CoRIM.
	CorimFile string
	// Format is either FormatCBOR or FormatJSON.
	Format string
	// Seed, when set, derives the generated CoRIM and CoMID ids from it
	// rather than drawing them at random, so that an unsigned run can be
	// reproduced byte for byte.
	Seed string
	// IDPrefix, when set, turns the generated ids from UUIDs into strings of
	// the prefix followed by the UUID.
	IDPrefix string
	// SigningKey, when set, is the path of a JWK used to produce a signed
	// CoRIM rather than an unsigned one.
	SigningKey string
}

// Valid returns an error if the supplied options are inconsistent.
func (o *Options) Valid() error {
	if o.TemplateDir == "" {
		return fmt.Errorf("template directory not specified")
	}

	if o.Format != FormatCBOR && o.Format != FormatJSON {
		return fmt.Errorf("unsupported format %q, want %q or %q",
			o.Format, FormatCBOR, FormatJSON)
	}

	// A signed CoRIM is a COSE Sign1 message, for which no JSON
	// serialization is defined.
	if o.SigningKey != "" && o.Format == FormatJSON {
		return errSignedJSON
	}

	return nil
}
