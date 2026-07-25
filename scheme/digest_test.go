// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package scheme

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/veraison/corim/comid"
)

func Test_DigestAlgorithm(t *testing.T) {
	for _, tv := range []struct {
		name     string
		algName  string
		valueLen int
		expected int
		err      string
	}{
		{
			name:     "unnamed, inferred from the length",
			valueLen: 32,
			expected: comid.Sha256,
		},
		{
			name:     "unnamed, 48 bytes",
			valueLen: 48,
			expected: comid.Sha384,
		},
		{
			name:     "unnamed, 64 bytes",
			valueLen: 64,
			expected: comid.Sha512,
		},
		{
			name:     "named and consistent",
			algName:  "sha-384",
			valueLen: 48,
			expected: comid.Sha384,
		},
		{
			name:     "named and consistent, 64 bytes",
			algName:  "sha-512",
			valueLen: 64,
			expected: comid.Sha512,
		},
		{
			// the name is the only thing that can tell these apart
			name:     "named, same length as another algorithm",
			algName:  "sha3-256",
			valueLen: 32,
			expected: comid.Sha3_256,
		},
		{
			// the token contradicts itself; picking either half
			// silently would bury that
			name:     "named but inconsistent",
			algName:  "sha-256",
			valueLen: 64,
			err: `the token names hash algorithm "sha-256" for a measurement value of 64 bytes: ` +
				"length mismatch for hash algorithm sha-256: want 32 bytes, got 64",
		},
		{
			// how the TF-M vectors spell it
			name:     "vendor spelling",
			algName:  "SHA256",
			valueLen: 32,
			expected: comid.Sha256,
		},
		{
			name:     "vendor spelling, still cross-checked",
			algName:  "SHA256",
			valueLen: 64,
			err: `the token names hash algorithm "SHA256" for a measurement value of 64 bytes: ` +
				"length mismatch for hash algorithm sha-256: want 32 bytes, got 64",
		},
		{
			name:     "unknown name",
			algName:  "not-a-hash",
			valueLen: 32,
			err:      `unknown hash algorithm "not-a-hash"`,
		},
		{
			name:     "unknown length",
			valueLen: 20,
			err:      "cannot determine the hash algorithm of a 20 byte measurement value",
		},
		{
			name:     "named, unknown length",
			algName:  "sha-256",
			valueLen: 20,
			err:      "cannot determine the hash algorithm of a 20 byte measurement value",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			algID, err := DigestAlgorithm(make([]byte, tv.valueLen), tv.algName)

			if tv.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tv.expected, algID)
			} else {
				assert.EqualError(t, err, tv.err)
			}
		})
	}
}

func Test_normalizeAlgorithmName(t *testing.T) {
	for _, tv := range []struct{ in, expected string }{
		{"sha-256", "sha-256"},
		{"SHA-256", "sha-256"},
		{"SHA256", "sha-256"},
		{"sha512", "sha-512"},
		{" Sha384 ", "sha-384"},
		{"sha_256", "sha-256"},
		{"sha3-256", "sha3-256"},
		{"SHA3-512", "sha3-512"},
		{"not-a-hash", "not-a-hash"},
	} {
		t.Run(tv.in, func(t *testing.T) {
			assert.Equal(t, tv.expected, normalizeAlgorithmName(tv.in))
		})
	}
}
