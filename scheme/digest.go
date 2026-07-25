// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package scheme

import (
	"fmt"
	"strings"

	"github.com/veraison/corim/comid"
)

var digestAlgorithmForLength = map[int]int{
	32: comid.Sha256,
	48: comid.Sha384,
	64: comid.Sha512,
}

// DigestAlgorithm returns the hash algorithm of a measurement value.
//
// name is the algorithm the token states for that value, and may be empty. It
// has to agree with the value it describes; a name that disagrees is an error,
// since the claims contradict each other and either could be the wrong one.
//
// Without a name the length decides, which only identifies the family: a name
// is what separates SHA-256 from SHA3-256.
func DigestAlgorithm(value []byte, name string) (int, error) {
	byLength, ok := digestAlgorithmForLength[len(value)]
	if !ok {
		return 0, fmt.Errorf(
			"cannot determine the hash algorithm of a %d byte measurement value", len(value))
	}

	if name == "" {
		return byLength, nil
	}

	algID := comid.DigestAlgorithmFromString(normalizeAlgorithmName(name)).Int()
	if algID == 0 {
		return 0, fmt.Errorf("unknown hash algorithm %q", name)
	}

	// Valid applies the library's own algorithm-to-length table.
	if err := comid.NewDigest(comid.IntDigestAlgorithm(algID), value).Valid(); err != nil {
		return 0, fmt.Errorf(
			"the token names hash algorithm %q for a measurement value of %d bytes: %w",
			name, len(value), err)
	}

	return algID, nil
}

// normalizeAlgorithmName maps the spellings tokens use onto the registry names
// the corim library knows: the registry says "sha-256", the TF-M vectors say
// "SHA256".
func normalizeAlgorithmName(name string) string {
	normalized := strings.ToLower(strings.TrimSpace(name))
	normalized = strings.ReplaceAll(normalized, "_", "-")

	// "sha256" -> "sha-256", leaving "sha-256" and "sha3-256" alone
	if rest, ok := strings.CutPrefix(normalized, "sha"); ok {
		if !strings.HasPrefix(rest, "-") && !strings.HasPrefix(rest, "3-") {
			normalized = "sha-" + rest
		}
	}

	return normalized
}
