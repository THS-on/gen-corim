// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
)

// TestProfile is a profile that has no extensions registered with the corim
// library, so that the pipeline tests exercise base CoRIM validation only.
const TestProfile = "http://example.com/test-profile"

var (
	testCorimTemplate = []byte(`{
    "entities": [
        {
            "name": "ACME Ltd.",
            "regid": "acme.example",
            "roles": [ "manifestCreator" ]
        }
    ]
}`)

	testComidTemplate = []byte(`{
    "lang": "en-GB",
    "tag-identity": {
        "version": 1
    },
    "entities": [
        {
            "name": "ACME Ltd.",
            "regid": "https://acme.example",
            "roles": [ "tagCreator", "creator", "maintainer" ]
        }
    ]
}`)

	testMetaTemplate = []byte(`{
    "signer": {
        "name": "ACME Ltd.",
        "uri": "https://acme.example"
    }
}`)

	// testSigningKey is the ES256 key used to sign CoRIMs in tests.
	testSigningKey = []byte(`{
    "kty": "EC",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
}`)
)

// testFs returns an in-memory filesystem holding a complete template directory
// and a signing key.
func testFs(t *testing.T) afero.Fs {
	t.Helper()

	fs := afero.NewMemMapFs()

	require.NoError(t, afero.WriteFile(fs, "templates/"+CorimTemplateName, testCorimTemplate, 0644))
	require.NoError(t, afero.WriteFile(fs, "templates/"+ComidTemplateName, testComidTemplate, 0644))
	require.NoError(t, afero.WriteFile(fs, "templates/"+MetaTemplateName, testMetaTemplate, 0644))
	require.NoError(t, afero.WriteFile(fs, "key.json", testSigningKey, 0644))

	return fs
}

// testOptions returns options pointing at the directories laid out by testFs.
func testOptions() *Options {
	return &Options{
		TemplateDir: "templates",
		OutputDir:   "out",
		Format:      FormatCBOR,
	}
}

// addTestRefVal populates m with a minimal, valid reference value.
func addTestRefVal(t *testing.T, m *comid.Comid, vendor string) {
	t.Helper()

	meas, err := comid.NewUintMeasurement(uint(0))
	require.NoError(t, err)
	meas.AddDigest(comid.Sha256, make([]byte, 32))

	ms := comid.NewMeasurements()
	ms.Add(meas)

	classID, err := comid.ParseUUID("31fb5abf-023e-4992-aa4e-95f9c1503bfa")
	require.NoError(t, err)

	m.Triples.AddReferenceValue(&comid.ValueTriple{
		Environment: comid.Environment{
			Class: comid.NewClassUUID(classID).SetVendor(vendor),
		},
		Measurements: *ms,
	})
}
