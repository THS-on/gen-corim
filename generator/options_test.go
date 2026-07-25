// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Options_Valid(t *testing.T) {
	for _, tv := range []struct {
		name     string
		opts     Options
		expected string
	}{
		{
			name: "ok",
			opts: Options{TemplateDir: "templates", Format: FormatCBOR},
		},
		{
			name: "ok, json",
			opts: Options{TemplateDir: "templates", Format: FormatJSON},
		},
		{
			name:     "no template dir",
			opts:     Options{Format: FormatCBOR},
			expected: "template directory not specified",
		},
		{
			name:     "bad format",
			opts:     Options{TemplateDir: "templates", Format: "diag"},
			expected: `unsupported format "diag", want "cbor" or "json"`,
		},
		{
			name:     "signed JSON",
			opts:     Options{TemplateDir: "templates", Format: FormatJSON, SigningKey: "key.json"},
			expected: "a signed CoRIM cannot be serialized as JSON",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			err := tv.opts.Valid()

			if tv.expected == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tv.expected)
			}
		})
	}
}
