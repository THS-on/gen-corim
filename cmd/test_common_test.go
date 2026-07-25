// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/gen-corim/generator"
	"github.com/veraison/gen-corim/scheme"
)

// testProfile has no extensions registered with the corim library, so the
// command tests exercise base CoRIM validation only.
const testProfile = "http://example.com/test-profile"

// testScheme is a stand-in for a real attestation scheme. It exists to pin down
// the contract a scheme must satisfy, and to keep the command tests independent
// of any particular evidence format.
type testScheme struct {
	// labels are the payload labels to emit, one CoRIM per label.
	labels []string
	// fail makes Generate return an error, standing in for unparseable
	// evidence.
	fail bool
}

func newTestScheme() scheme.Scheme { return &testScheme{labels: []string{""}} }

// newMultiPartTestScheme emits two CoRIMs, as the CCA scheme does.
func newMultiPartTestScheme() scheme.Scheme {
	return &testScheme{labels: []string{"platform", "realm"}}
}

func newFailingTestScheme() scheme.Scheme { return &testScheme{fail: true} }

func (o *testScheme) Use() string   { return "test <evidence-file>" }
func (o *testScheme) Short() string { return "generate a test CoRIM" }
func (o *testScheme) Long() string  { return "generate a test CoRIM from test evidence" }

func (o *testScheme) Args() cobra.PositionalArgs { return cobra.ExactArgs(1) }

func (o *testScheme) AddFlags(flags *pflag.FlagSet) {
	flags.Bool("test-flag", false, "a scheme-specific flag")
}

func (o *testScheme) Generate(
	fs afero.Fs, b scheme.ComidBuilder, args []string,
) ([]scheme.Payload, error) {
	if o.fail {
		return nil, errors.New("error reading the evidence")
	}

	if _, err := afero.ReadFile(fs, args[0]); err != nil {
		return nil, err
	}

	payloads := make([]scheme.Payload, 0, len(o.labels))

	for _, label := range o.labels {
		m, err := b.NewComid(testProfile)
		if err != nil {
			return nil, err
		}

		meas, err := comid.NewUintMeasurement(uint(0))
		if err != nil {
			return nil, err
		}
		meas.AddDigest(comid.Sha256, make([]byte, 32))

		ms := comid.NewMeasurements()
		ms.Add(meas)

		classID, err := comid.ParseUUID("31fb5abf-023e-4992-aa4e-95f9c1503bfa")
		if err != nil {
			return nil, err
		}

		m.Triples.AddReferenceValue(&comid.ValueTriple{
			Environment:  comid.Environment{Class: comid.NewClassUUID(classID)},
			Measurements: *ms,
		})

		payloads = append(payloads, scheme.Payload{
			Profile: testProfile,
			Label:   label,
			Comids:  []*comid.Comid{m},
		})
	}

	return payloads, nil
}

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
    "lang": "en-GB"
}`)

	testMetaTemplate = []byte(`{
    "signer": {
        "name": "ACME Ltd.",
        "uri": "https://acme.example"
    }
}`)

	testSigningKeyJWK = []byte(`{
    "kty": "EC",
    "crv": "P-256",
    "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
}`)
)

// testSigningKey is where testFs writes the signing key.
const testSigningKey = "key.json"

// testFs returns an in-memory filesystem holding a template directory and a
// stand-in evidence file.
func testFs(t *testing.T) afero.Fs {
	t.Helper()

	fs := afero.NewMemMapFs()

	require.NoError(t, afero.WriteFile(fs,
		"templates/"+generator.CorimTemplateName, testCorimTemplate, 0644))
	require.NoError(t, afero.WriteFile(fs,
		"templates/"+generator.ComidTemplateName, testComidTemplate, 0644))
	require.NoError(t, afero.WriteFile(fs,
		"templates/"+generator.MetaTemplateName, testMetaTemplate, 0644))
	require.NoError(t, afero.WriteFile(fs, testSigningKey, testSigningKeyJWK, 0644))
	require.NoError(t, afero.WriteFile(fs, "evidence.cbor", []byte("evidence"), 0644))

	return fs
}
