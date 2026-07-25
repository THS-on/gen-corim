// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/veraison/gen-corim/scheme"
	"github.com/veraison/gen-corim/schemes/cca"
	"github.com/veraison/gen-corim/schemes/psa"
)

// DefaultSchemes lists the attestation schemes gen-corim supports. Adding a
// scheme means adding its package and one entry here.
var DefaultSchemes = []scheme.Factory{
	psa.New,
	cca.New,
}
