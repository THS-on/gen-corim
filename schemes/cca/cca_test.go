// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

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
	"github.com/veraison/gen-corim/generator"
	"github.com/veraison/gen-corim/scheme"
)

// update regenerates the golden CoRIMs instead of comparing against them.
var update = flag.Bool("update", false, "regenerate the golden CoRIMs")

const (
	// tfRmmToken is a full CCA token in the CMW collection encoding, with
	// both platform and realm claims.
	tfRmmToken = "../../data/cca/tf-rmm/cca_token.cbor"

	// legacyToken uses the deprecated collection encoding that ccatoken
	// still accepts.
	legacyToken = "../../data/cca/cca-evidence.cbor"

	psaToken     = "../../data/psa/psa-evidence.cbor"
	testTemplate = "../../data/templates/cca"

	goldenDir = "../../data/golden"
)

// newFlagSet returns the scheme's flags, bound to that scheme instance.
func newFlagSet(t *testing.T, s scheme.Scheme) *pflag.FlagSet {
	t.Helper()

	flags := pflag.NewFlagSet("cca", pflag.ContinueOnError)
	s.AddFlags(flags)

	return flags
}

// generate runs the scheme over the supplied arguments. The first argument is
// the token; the rest are flags.
func generate(t *testing.T, args ...string) ([]scheme.Payload, error) {
	t.Helper()

	fs := afero.NewOsFs()

	s := New()

	flags := newFlagSet(t, s)
	require.NoError(t, flags.Parse(args[1:]))

	opts := &generator.Options{TemplateDir: testTemplate, Format: generator.FormatCBOR}

	g, err := generator.New(fs, opts, "cca")
	require.NoError(t, err)

	return s.Generate(fs, g, args[:1])
}

// platformOf returns the platform CoMID of the generated payloads.
func platformOf(t *testing.T, payloads []scheme.Payload) *comid.Comid {
	t.Helper()

	for _, payload := range payloads {
		if payload.Label == PartPlatform {
			require.Len(t, payload.Comids, 1)
			return payload.Comids[0]
		}
	}

	t.Fatal("no platform payload generated")

	return nil
}

// realmOf returns the realm CoMID of the generated payloads.
func realmOf(t *testing.T, payloads []scheme.Payload) *comid.Comid {
	t.Helper()

	for _, payload := range payloads {
		if payload.Label == PartRealm {
			require.Len(t, payload.Comids, 1)
			return payload.Comids[0]
		}
	}

	t.Fatal("no realm payload generated")

	return nil
}

// measurementKeys returns the measurement keys of the CoMID's single reference
// value, in order.
func measurementKeys(t *testing.T, m *comid.Comid) []string {
	t.Helper()

	require.NotNil(t, m.Triples.ReferenceValues)
	require.Len(t, m.Triples.ReferenceValues.Values, 1)

	values := m.Triples.ReferenceValues.Values[0].Measurements.Values
	keys := make([]string, 0, len(values))

	for i := range values {
		require.NotNil(t, values[i].Key)
		keys = append(keys, values[i].Key.Value.String())
	}

	return keys
}

func Test_Generate_platform(t *testing.T) {
	payloads, err := generate(t, tfRmmToken, "--part="+PartPlatform)
	require.NoError(t, err)
	require.Len(t, payloads, 1)
	assert.Equal(t, "tag:arm.com,2025:cca_platform#1.0.0", payloads[0].Profile)

	m := platformOf(t, payloads)

	// the generated CoMID must satisfy the CCA platform profile constraints
	require.NoError(t, m.Valid())

	require.NotNil(t, m.Triples.ReferenceValues)
	require.Len(t, m.Triples.ReferenceValues.Values, 1)

	refVal := m.Triples.ReferenceValues.Values[0]

	require.NotNil(t, refVal.Environment.Class)
	require.NotNil(t, refVal.Environment.Class.ClassID)
	assert.Len(t, refVal.Environment.Class.ClassID.Bytes(), 32)

	// software components, then exactly one platform configuration
	var software, config int

	for _, meas := range refVal.Measurements.Values {
		require.NotNil(t, meas.Key)
		assert.Equal(t, comid.StringType, meas.Key.Type())

		switch meas.Key.Value.String() {
		case "cca.software-component":
			software++
			require.NotNil(t, meas.Val.Digests)
			require.NotNil(t, meas.Val.CryptoKeys)
			// see platformMeasurements: no version can be carried
			assert.Nil(t, meas.Val.Ver)
		case "cca.platform-config":
			config++
			require.NotNil(t, meas.Val.RawValue)
			// the profile makes the mask mandatory alongside the value
			require.NotNil(t, meas.Val.RawValueMask)
		default:
			t.Fatalf("unexpected measurement key %q", meas.Key.Value.String())
		}
	}

	assert.Positive(t, software)
	assert.Equal(t, 1, config)
}

func Test_Generate_realm(t *testing.T) {
	payloads, err := generate(t, tfRmmToken, "--part="+PartRealm)
	require.NoError(t, err)
	require.Len(t, payloads, 1)
	assert.Equal(t, "tag:arm.com,2025:cca_realm#1.0.0", payloads[0].Profile)

	m := realmOf(t, payloads)

	// the generated CoMID must satisfy the CCA realm profile constraints
	require.NoError(t, m.Valid())

	refVal := m.Triples.ReferenceValues.Values[0]

	// the realm is identified by its initial measurement, which is also
	// carried as a measurement of its own
	require.NotNil(t, refVal.Environment.Class)
	require.NotNil(t, refVal.Environment.Class.ClassID)

	rim := refVal.Environment.Class.ClassID.Bytes()
	assert.Contains(t, []int{32, 48, 64}, len(rim))

	require.NotNil(t, refVal.Measurements.Values[0].Val.Digests)
	assert.Equal(t, rim, (*refVal.Measurements.Values[0].Val.Digests)[0].Value)

	// the initial measurement, the four extensible registers, and the
	// personalization value this token happens to carry
	assert.Equal(t, []string{
		"cca.rim", "cca.rem0", "cca.rem1", "cca.rem2", "cca.rem3", "cca.rpv",
	}, measurementKeys(t, m))

	// the personalization value is a raw value rather than a digest
	rpv := refVal.Measurements.Values[5]
	assert.Nil(t, rpv.Val.Digests)
	require.NotNil(t, rpv.Val.RawValue)

	// a realm is identified by its measurements, not by a key
	assert.Nil(t, m.Triples.AttestVerifKeys)
}

// The realm hash-alg-id claim of the legacy vector names SHA-256 while its
// measurements are 64 bytes long, and ccatoken accepts that because it only
// checks the claim is a non-empty string.
//
// Both halves come from the same token and one of them is wrong. Generating a
// CoRIM from either would assert something the attester did not, so the
// contradiction is reported rather than resolved.
func Test_Generate_realm_inconsistent_hash_alg_claim(t *testing.T) {
	_, err := generate(t, legacyToken, "--part="+PartRealm)

	assert.ErrorContains(t, err,
		`cca.rim: the token names hash algorithm "sha-256" for a measurement value of 64 bytes`)

	// and the same when both parts are asked for, rather than silently
	// emitting only the platform one
	_, err = generate(t, legacyToken)
	assert.ErrorContains(t, err, "the token names hash algorithm")
}

// The platform measurements of the same vector are consistent with its platform
// hash-alg-id claim, so that half is generated normally. It also covers the
// deprecated collection encoding, which must be accepted just like the CMW one.
func Test_Generate_platform_hash_alg_claim_is_used(t *testing.T) {
	payloads, err := generate(t, legacyToken, "--part="+PartPlatform)
	require.NoError(t, err)
	require.Len(t, payloads, 1)

	m := platformOf(t, payloads)
	require.NoError(t, m.Valid())

	for _, meas := range m.Triples.ReferenceValues.Values[0].Measurements.Values {
		if meas.Val.Digests == nil {
			continue // the platform configuration is a raw value
		}

		digest := (*meas.Val.Digests)[0]
		require.Len(t, digest.Value, 32)
		assert.Equal(t, "sha-256", digest.Algorithm.String())
	}
}

func Test_Generate_both_parts(t *testing.T) {
	payloads, err := generate(t, tfRmmToken)
	require.NoError(t, err)
	require.Len(t, payloads, 2)

	assert.Equal(t, PartPlatform, payloads[0].Label)
	assert.Equal(t, PartRealm, payloads[1].Label)

	// the two CoRIMs are of different profiles, which is why they cannot be
	// merged into one
	assert.NotEqual(t, payloads[0].Profile, payloads[1].Profile)
}

func Test_Generate_raw_value_mask_covers_the_whole_config(t *testing.T) {
	payloads, err := generate(t, tfRmmToken, "--part="+PartPlatform)
	require.NoError(t, err)

	m := platformOf(t, payloads)

	for _, meas := range m.Triples.ReferenceValues.Values[0].Measurements.Values {
		if meas.Key.Value.String() != "cca.platform-config" {
			continue
		}

		value := meas.Val.RawValue.Bytes()
		require.NotNil(t, value)

		mask := *meas.Val.RawValueMask
		require.Len(t, mask, len(value))

		for i, b := range mask {
			assert.Equal(t, byte(0xff), b, "mask byte %d", i)
		}

		return
	}

	t.Fatal("no platform configuration measurement generated")
}

func Test_Generate_errors(t *testing.T) {
	for _, tv := range []struct {
		name     string
		token    string
		args     []string
		expected string
	}{
		{
			name:     "bad part",
			token:    tfRmmToken,
			args:     []string{"--part=firmware"},
			expected: `unsupported part "firmware", want "platform", "realm" or "both"`,
		},
		{
			name:     "absent token",
			token:    "../../data/cca/absent.cbor",
			expected: "error loading token from",
		},
		{
			// a PSA token is not a CCA token, and must be rejected
			// rather than silently producing a half-populated CoRIM
			name:     "psa token",
			token:    psaToken,
			expected: "error decoding token from",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			_, err := generate(t, append([]string{tv.token}, tv.args...)...)
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

func Test_Generate_golden(t *testing.T) {
	fs := afero.NewOsFs()

	s := New()
	require.NoError(t, newFlagSet(t, s).Parse(nil))

	opts := &generator.Options{
		TemplateDir: testTemplate,
		OutputDir:   t.TempDir(),
		Format:      generator.FormatCBOR,
		Seed:        "golden",
	}

	g, err := generator.New(fs, opts, "cca")
	require.NoError(t, err)

	payloads, err := s.Generate(fs, g, []string{tfRmmToken})
	require.NoError(t, err)

	paths, err := g.Write(payloads)
	require.NoError(t, err)

	for _, path := range paths {
		got, err := afero.ReadFile(fs, path)
		require.NoError(t, err)

		golden := filepath.Join(goldenDir, filepath.Base(path))

		if *update {
			require.NoError(t, fs.MkdirAll(goldenDir, 0755))
			require.NoError(t, afero.WriteFile(fs, golden, got, 0644))
			continue
		}

		want, err := afero.ReadFile(fs, golden)
		require.NoError(t, err, "golden file missing; regenerate with -update")
		assert.Equal(t, want, got, golden)

		_, err = corim.UnmarshalAndValidateUnsignedCorimFromCBOR(want)
		assert.NoError(t, err, golden)
	}
}

// New must hand out independent flag state, so that one command cannot see the
// flags of another: --part on the first instance must leave the second one on the
// default, which generates both parts.
func Test_New_returns_independent_instances(t *testing.T) {
	fs := afero.NewOsFs()

	opts := &generator.Options{TemplateDir: testTemplate, Format: generator.FormatCBOR}
	g, err := generator.New(fs, opts, "cca")
	require.NoError(t, err)

	first := New()
	require.NoError(t, newFlagSet(t, first).Parse([]string{"--part=" + PartPlatform}))

	second := New()
	require.NoError(t, newFlagSet(t, second).Parse(nil))

	payloads, err := first.Generate(fs, g, []string{tfRmmToken})
	require.NoError(t, err)
	assert.Len(t, payloads, 1)

	payloads, err = second.Generate(fs, g, []string{tfRmmToken})
	require.NoError(t, err)
	assert.Len(t, payloads, 2)
}
