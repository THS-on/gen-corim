// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"
	"github.com/veraison/gen-corim/scheme"
)

// run executes the root command with the supplied arguments, returning whatever
// it wrote to stdout together with the resulting error.
func run(t *testing.T, fs afero.Fs, factories []scheme.Factory, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer

	cmd := NewRootCmd(fs, factories...)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)

	err := cmd.Execute()

	return out.String(), err
}

func Test_RootCmd_help(t *testing.T) {
	factories := []scheme.Factory{newTestScheme}

	out, err := run(t, testFs(t), factories, "--help")
	require.NoError(t, err)
	assert.Contains(t, out, "Generate a CoRIM from an attestation token or platform report.")
	assert.Contains(t, out, "--template-dir")
	assert.Contains(t, out, "--signing-key")
	assert.Contains(t, out, "--signing-cert")
	assert.Contains(t, out, "--intermediate-certs")
	assert.Contains(t, out, "generate a test CoRIM")

	// the scheme binds its own flags, and documents itself
	out, err = run(t, testFs(t), factories, "test", "--help")
	require.NoError(t, err)
	assert.Contains(t, out, "generate a test CoRIM from test evidence")
	assert.Contains(t, out, "--test-flag")
}

func Test_RootCmd_version(t *testing.T) {
	out, err := run(t, afero.NewMemMapFs(), nil, "--version")
	require.NoError(t, err)
	assert.Equal(t, "gen-corim version "+Version+"\n", out)
}

// The generator options are reached only through the persistent flags, so each
// case pins both that the flag arrives and what it does to the output.
func Test_SchemeCmd_generates(t *testing.T) {
	unsigned := func(t *testing.T, data []byte) {
		t.Helper()

		_, err := corim.UnmarshalAndValidateUnsignedCorimFromCBOR(data)
		assert.NoError(t, err)
	}

	for _, tv := range []struct {
		name   string
		args   []string
		path   string
		verify func(t *testing.T, data []byte)
	}{
		{
			name:   "cbor",
			args:   []string{"--output-dir=out"},
			path:   "out/test-endorsements.cbor",
			verify: unsigned,
		},
		{
			name: "json",
			args: []string{"--output-dir=out", "--format=json"},
			path: "out/test-endorsements.json",
			verify: func(t *testing.T, data []byte) {
				t.Helper()

				var uc corim.UnsignedCorim
				require.NoError(t, uc.FromJSON(data))
				assert.Equal(t, testProfile, uc.Profile.String())
			},
		},
		{
			name: "signed",
			args: []string{"--output-dir=out", "--signing-key=" + testSigningKey},
			path: "out/test-endorsements.cbor",
			verify: func(t *testing.T, data []byte) {
				t.Helper()

				var sc corim.SignedCorim
				require.NoError(t, sc.FromCOSE(data))
				assert.Equal(t, "ACME Ltd.", sc.Meta.Signer.Name)
			},
		},
		{
			name:   "corim-file",
			args:   []string{"--corim-file=out/mine.cbor"},
			path:   "out/mine.cbor",
			verify: unsigned,
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			fs := testFs(t)
			args := append(
				[]string{"test", "evidence.cbor", "--template-dir=templates"}, tv.args...)

			out, err := run(t, fs, []scheme.Factory{newTestScheme}, args...)
			require.NoError(t, err)
			assert.Contains(t, out, fmt.Sprintf(">> generated %q", tv.path))

			data, err := afero.ReadFile(fs, tv.path)
			require.NoError(t, err)
			tv.verify(t, data)
		})
	}
}

// Reproducibility is what --seed exists for: two runs given the same one must
// write the same bytes.
func Test_SchemeCmd_seed_reproduces_the_output(t *testing.T) {
	fs := testFs(t)

	outputs := make([]string, 0, 2)

	for _, dir := range []string{"first", "second"} {
		_, err := run(t, fs, []scheme.Factory{newTestScheme}, "test", "evidence.cbor",
			"--template-dir=templates", "--output-dir="+dir, "--format=json",
			"--seed=x", "--id-prefix=acme-")
		require.NoError(t, err)

		data, err := afero.ReadFile(fs, dir+"/test-endorsements.json")
		require.NoError(t, err)

		outputs = append(outputs, string(data))
	}

	assert.Equal(t, outputs[0], outputs[1])
	assert.Contains(t, outputs[0], `"corim-id":"acme-`)
}

func Test_SchemeCmd_generates_multiple(t *testing.T) {
	fs := testFs(t)
	factories := []scheme.Factory{newMultiPartTestScheme}

	out, err := run(t, fs, factories,
		"test", "evidence.cbor", "--template-dir=templates", "--output-dir=out")
	require.NoError(t, err)
	assert.Contains(t, out, `>> generated "out/test-platform-endorsements.cbor"`)
	assert.Contains(t, out, `>> generated "out/test-realm-endorsements.cbor"`)
}

func Test_SchemeCmd_errors(t *testing.T) {
	for _, tv := range []struct {
		name     string
		factory  scheme.Factory
		args     []string
		expected string
	}{
		{
			name:     "no evidence file",
			factory:  newTestScheme,
			args:     []string{"test", "--template-dir=templates"},
			expected: "accepts 1 arg(s), received 0",
		},
		{
			name:     "bad format",
			factory:  newTestScheme,
			args:     []string{"test", "evidence.cbor", "--template-dir=templates", "--format=diag"},
			expected: `unsupported format "diag"`,
		},
		{
			// not a flag group either: --signing-key is usable on its
			// own, it is only the certificate that depends on it
			name:    "signing cert without a signing key",
			factory: newTestScheme,
			args: []string{"test", "evidence.cbor",
				"--template-dir=templates", "--signing-cert=cert.der"},
			expected: "a signing certificate is only meaningful with a signing key",
		},
		{
			name:     "scheme failure",
			factory:  newFailingTestScheme,
			args:     []string{"test", "evidence.cbor", "--template-dir=templates"},
			expected: "error reading the evidence",
		},
		{
			// not a flag group either: --format takes a value, so the
			// combination is only visible to Options.Valid
			name:    "signed JSON",
			factory: newTestScheme,
			args: []string{"test", "evidence.cbor", "--template-dir=templates",
				"--signing-key=" + testSigningKey, "--format=json"},
			expected: "a signed CoRIM cannot be serialized as JSON",
		},
		{
			// not a flag group: how many CoRIMs a run produces is
			// only known once the evidence has been read
			name:    "corim-file for several CoRIMs",
			factory: newMultiPartTestScheme,
			args: []string{"test", "evidence.cbor",
				"--template-dir=templates", "--corim-file=out/mine.cbor"},
			expected: "--corim-file",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			fs := testFs(t)

			_, err := run(t, fs, []scheme.Factory{tv.factory}, tv.args...)
			assert.ErrorContains(t, err, tv.expected)

			// the options are checked before any evidence is read, so a
			// run that errors leaves nothing behind
			written, err := afero.Glob(fs, "*endorsements*")
			require.NoError(t, err)
			assert.Empty(t, written)
		})
	}
}

func Test_SchemeCmd_output_dir_and_corim_file_conflict(t *testing.T) {
	fs := testFs(t)
	factories := []scheme.Factory{newTestScheme}

	_, err := run(t, fs, factories, "test", "evidence.cbor",
		"--template-dir=templates", "--output-dir=out", "--corim-file=out/mine.cbor")
	require.Error(t, err)
	assert.ErrorContains(t, err, "output-dir")
	assert.ErrorContains(t, err, "corim-file")

	for _, path := range []string{"out/mine.cbor", "out/test-endorsements.cbor"} {
		exists, err := afero.Exists(fs, path)
		require.NoError(t, err)
		assert.False(t, exists, "nothing should have been written to %s", path)
	}
}

// Each command build must get its own flag state, so that a flag set on one
// command cannot leak into the next.
func Test_NewRootCmd_does_not_share_flag_state(t *testing.T) {
	factories := []scheme.Factory{newTestScheme}

	fs := testFs(t)
	_, err := run(t, fs, factories, "test", "evidence.cbor",
		"--template-dir=templates", "--output-dir=first")
	require.NoError(t, err)

	// a second command, without --output-dir, must fall back to the default
	_, err = run(t, fs, factories, "test", "evidence.cbor", "--template-dir=templates")
	require.NoError(t, err)

	exists, err := afero.Exists(fs, "test-endorsements.cbor")
	require.NoError(t, err)
	assert.True(t, exists, "second run should have used the default output directory")
}
