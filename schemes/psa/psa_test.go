// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package psa

import (
	"flag"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	corimpsa "github.com/veraison/corim/profiles/psa"
	"github.com/veraison/gen-corim/generator"
	"github.com/veraison/gen-corim/scheme"
)

// update regenerates the golden CoRIMs instead of comparing against them.
var update = flag.Bool("update", false, "regenerate the golden CoRIMs")

const (
	testToken    = "../../data/psa/psa-evidence.cbor"
	testKey      = "../../data/keys/es256-pub.json"
	testWrongKey = "../../data/keys/wrong-es256.json"

	// a certificate over testKey, and the anchors that did and did not
	// issue it; see data/PROVENANCE.md
	testIAKCert  = "../../data/certs/iak.pem"
	testCA       = "../../data/certs/ca.pem"
	testOtherCA  = "../../data/certs/other-ca.pem"
	testTemplate = "../../data/templates/psa"

	tfmP1Token   = "../../data/psa/tfm/psa-iot-1_sign1.bin"
	tfmP2Token   = "../../data/psa/tfm/psa-2_0_0_sign1.bin"
	tfmPublicPEM = "../../data/psa/tfm/public.pem"

	goldenDir = "../../data/golden"
)

// newFlagSet returns the scheme's flags, bound to that scheme instance.
func newFlagSet(t *testing.T, s scheme.Scheme) *pflag.FlagSet {
	t.Helper()

	flags := pflag.NewFlagSet("psa", pflag.ContinueOnError)
	s.AddFlags(flags)

	return flags
}

// generate runs the scheme over the supplied arguments and returns the
// resulting CoMID. The first argument is the token; the rest are flags.
func generate(t *testing.T, args ...string) (*comid.Comid, error) {
	t.Helper()

	fs := afero.NewOsFs()

	s := New()

	flags := newFlagSet(t, s)
	require.NoError(t, flags.Parse(args[1:]))

	opts := &generator.Options{TemplateDir: testTemplate, Format: generator.FormatCBOR}

	g, err := generator.New(fs, opts, "psa")
	require.NoError(t, err)

	payloads, err := s.Generate(fs, g, args[:1])
	if err != nil {
		return nil, err
	}

	require.Len(t, payloads, 1)
	require.Equal(t, corimpsa.ProfileURI, payloads[0].Profile)
	require.Len(t, payloads[0].Comids, 1)

	return payloads[0].Comids[0], nil
}

func Test_Generate_psa_evidence(t *testing.T) {
	m, err := generate(t, testToken, "--key="+testKey)
	require.NoError(t, err)

	// the generated CoMID must satisfy the PSA profile constraints
	require.NoError(t, m.Valid())

	require.NotNil(t, m.Triples.ReferenceValues)
	require.Len(t, m.Triples.ReferenceValues.Values, 1)

	refVal := m.Triples.ReferenceValues.Values[0]

	// the environment carries the 32 byte implementation ID from the token
	require.NotNil(t, refVal.Environment.Class)
	require.NotNil(t, refVal.Environment.Class.ClassID)
	assert.Equal(t, "bytes", refVal.Environment.Class.ClassID.Type())
	assert.Len(t, refVal.Environment.Class.ClassID.Bytes(), 32)

	// one measurement per software component, each keyed by the string
	// mandated by the profile and carrying a digest and a signer ID
	require.Len(t, refVal.Measurements.Values, 3)

	for i, meas := range refVal.Measurements.Values {
		require.NotNil(t, meas.Key, "measurement %d", i)
		assert.Equal(t, comid.StringType, meas.Key.Type())
		assert.Equal(t, corimpsa.PSASoftwareComponentMkey, meas.Key.Value.String())

		require.NotNil(t, meas.Val.Digests)
		require.Len(t, *meas.Val.Digests, 1)
		assert.Len(t, (*meas.Val.Digests)[0].Value, 32)

		require.NotNil(t, meas.Val.CryptoKeys)
		require.Len(t, *meas.Val.CryptoKeys, 1)
		assert.Equal(t, "bytes", (*meas.Val.CryptoKeys)[0].Type())
	}

	// measurement type and version are carried across when present
	assert.Equal(t, "BL", *refVal.Measurements.Values[0].Val.Name)
	require.NotNil(t, refVal.Measurements.Values[0].Val.Ver)
	assert.Equal(t, "2.1.0", refVal.Measurements.Values[0].Val.Ver.Version)

	// the attestation verification key triple carries the instance ID and
	// the supplied key
	require.NotNil(t, m.Triples.AttestVerifKeys)
	require.Len(t, *m.Triples.AttestVerifKeys, 1)

	avk := (*m.Triples.AttestVerifKeys)[0]
	require.NotNil(t, avk.Environment.Instance)
	assert.Equal(t, comid.UEIDType, avk.Environment.Instance.Type())
	assert.Len(t, avk.Environment.Instance.Bytes(), 33)

	require.Len(t, avk.VerifKeys, 1)
	assert.Equal(t, comid.PKIXBase64KeyType, avk.VerifKeys[0].Type())
}

func Test_Generate_tfm_vectors(t *testing.T) {
	for _, tv := range []struct {
		name  string
		token string
	}{
		{name: "PSA_IOT_PROFILE_1", token: tfmP1Token},
		{name: "http://arm.com/psa/2.0.0", token: tfmP2Token},
	} {
		t.Run(tv.name, func(t *testing.T) {
			m, err := generate(t, tv.token, "--key="+tfmPublicPEM)
			require.NoError(t, err)
			require.NoError(t, m.Valid())

			require.NotNil(t, m.Triples.ReferenceValues)
			assert.NotEmpty(t, m.Triples.ReferenceValues.Values[0].Measurements.Values)

			// the TF-M tokens are signed by a different key than the
			// other vectors, so this pins down that the signature is
			// really being checked rather than waved through
			_, err = generate(t, tv.token, "--key="+testKey)
			assert.ErrorContains(t, err, "signature verification failed")
		})
	}
}

// --skip-verify suppresses the signature check, so whatever key is supplied is
// taken at face value, and none at all is no longer an error.
func Test_Generate_skip_verify(t *testing.T) {
	for _, tv := range []struct {
		name string
		args []string
		// keys is whether an attestation verification key triple is
		// expected: there is one only if a key was supplied.
		keys bool
	}{
		{name: "without a key", args: []string{"--skip-verify"}},
		{name: "with a wrong key", args: []string{"--key=" + testWrongKey, "--skip-verify"}, keys: true},
	} {
		t.Run(tv.name, func(t *testing.T) {
			m, err := generate(t, append([]string{testToken}, tv.args...)...)
			require.NoError(t, err)
			require.NoError(t, m.Valid())

			require.NotNil(t, m.Triples.ReferenceValues)

			if tv.keys {
				assert.NotNil(t, m.Triples.AttestVerifKeys)
			} else {
				assert.Nil(t, m.Triples.AttestVerifKeys)
			}
		})
	}
}

// An IAK certificate verified to its trust anchor is the strongest thing --key
// can say: without --trust-anchors the certificate is taken at face value.
func Test_Generate_certificate_chain(t *testing.T) {
	t.Run("verified to its anchor", func(t *testing.T) {
		m, err := generate(t, testToken, "--key="+testIAKCert, "--trust-anchors="+testCA)
		require.NoError(t, err)
		assert.NotNil(t, m.Triples.AttestVerifKeys)
	})

	t.Run("without anchors, taken at face value", func(t *testing.T) {
		m, err := generate(t, testToken, "--key="+testIAKCert)
		require.NoError(t, err)
		assert.NotNil(t, m.Triples.AttestVerifKeys)
	})

	t.Run("an anchor that did not issue it", func(t *testing.T) {
		_, err := generate(t, testToken, "--key="+testIAKCert, "--trust-anchors="+testOtherCA)
		assert.ErrorContains(t, err, "error verifying the certificate in")
	})
}

func Test_Generate_errors(t *testing.T) {
	for _, tv := range []struct {
		name     string
		token    string
		args     []string
		expected string
	}{
		{
			name:     "no key",
			token:    testToken,
			expected: "no key supplied: use --key, or --skip-verify to generate from an unverified token",
		},
		{
			name:     "wrong key",
			token:    testToken,
			args:     []string{"--key=" + testWrongKey},
			expected: "error verifying token",
		},
		{
			name:     "absent token",
			token:    "../../data/psa/absent.cbor",
			args:     []string{"--key=" + testKey},
			expected: "error loading token from",
		},
		{
			name:     "absent key",
			token:    testToken,
			args:     []string{"--key=../../data/keys/absent.json"},
			expected: "error loading key from",
		},
		{
			// a JWK is not a token
			name:     "not a token",
			token:    testKey,
			args:     []string{"--key=" + testKey},
			expected: "error decoding token from",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			_, err := generate(t, append([]string{tv.token}, tv.args...)...)
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

// The generated CoRIM is compared byte for byte against a golden file, so that
// a change in the output shape has to be acknowledged. Regenerate with
// "go test ./... -update".
func Test_Generate_golden(t *testing.T) {
	fs := afero.NewOsFs()

	s := New()
	flags := newFlagSet(t, s)
	require.NoError(t, flags.Parse([]string{"--key=" + testKey}))

	opts := &generator.Options{
		TemplateDir: testTemplate,
		OutputDir:   t.TempDir(),
		Format:      generator.FormatCBOR,
		Seed:        "golden",
	}

	g, err := generator.New(fs, opts, "psa")
	require.NoError(t, err)

	payloads, err := s.Generate(fs, g, []string{testToken})
	require.NoError(t, err)

	paths, err := g.Write(payloads)
	require.NoError(t, err)
	require.Len(t, paths, 1)

	got, err := afero.ReadFile(fs, paths[0])
	require.NoError(t, err)

	golden := filepath.Join(goldenDir, "psa-endorsements.cbor")

	if *update {
		require.NoError(t, fs.MkdirAll(goldenDir, 0755))
		require.NoError(t, afero.WriteFile(fs, golden, got, 0644))
		return
	}

	want, err := afero.ReadFile(fs, golden)
	require.NoError(t, err, "golden file missing; regenerate with -update")
	assert.Equal(t, want, got)

	// the golden file must also survive an independent decode, which
	// re-applies the PSA profile validation
	_, err = corim.UnmarshalAndValidateUnsignedCorimFromCBOR(want)
	assert.NoError(t, err)
}

// New must hand out independent flag state, so that one command cannot see the
// flags of another: the key parsed into the first instance must leave the second
// one without a key at all.
func Test_New_returns_independent_instances(t *testing.T) {
	fs := afero.NewOsFs()

	opts := &generator.Options{TemplateDir: testTemplate, Format: generator.FormatCBOR}
	g, err := generator.New(fs, opts, "psa")
	require.NoError(t, err)

	first := New()
	require.NoError(t, newFlagSet(t, first).Parse(
		[]string{"--key=" + testIAKCert, "--trust-anchors=" + testCA}))

	second := New()
	require.NoError(t, newFlagSet(t, second).Parse(nil))

	_, err = first.Generate(fs, g, []string{testToken})
	require.NoError(t, err)

	_, err = second.Generate(fs, g, []string{testToken})
	assert.ErrorContains(t, err, "no key supplied")
}
