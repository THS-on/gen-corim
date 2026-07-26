// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package scheme

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"
	"github.com/veraison/gen-corim/keyutil"
)

const (
	caFile      = "../data/certs/ca.pem"
	otherCAFile = "../data/certs/other-ca.pem"
	leafFile    = "../data/certs/iak.pem"
	keyFile     = "../data/keys/es256-pub.json"

	crlFile        = "../data/certs/crl.pem"
	revokingCRL    = "../data/certs/crl-revoked.pem"
	unrelatedCRL   = "../data/certs/other-crl.pem"
	certChainFile  = "../data/certs/cert-chain.pem"
	intermediateCA = "../data/certs/intermediate.pem"
)

// testNow sits inside the validity of every fixture, so that the tests do not
// depend on the day they run.
var testNow = time.Date(2030, time.June, 1, 0, 0, 0, 0, time.UTC)

func testFs() afero.Fs { return afero.NewOsFs() }

func certificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	cert, err := keyutil.CertificateFromFile(testFs(), path)
	require.NoError(t, err)

	return cert
}

func options(t *testing.T, cfg VerifyConfig, args ...string) *VerifyOptions {
	t.Helper()

	o := NewVerifyOptions(cfg)

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o.AddFlags(flags)
	require.NoError(t, flags.Parse(args))

	return &o
}

var (
	plainScheme   = VerifyConfig{KeyUsage: "key", SkipVerifyUsage: "skip"}
	builtinScheme = VerifyConfig{KeyUsage: "key", SkipVerifyUsage: "skip", HasBuiltinAnchors: true}
)

func Test_Resolve_modes(t *testing.T) {
	leaf := certificate(t, leafFile)

	for _, tv := range []struct {
		name   string
		cfg    VerifyConfig
		args   []string
		mode   Mode
		source AnchorSource
		leaf   bool
	}{
		{
			name: "no key at all",
			cfg:  plainScheme,
			mode: ModeKey,
		},
		{
			name: "a bare public key",
			cfg:  plainScheme,
			args: []string{"--key=" + keyFile},
			mode: ModeKey,
		},
		{
			// the key of a certificate nothing vouches for, which is
			// what the schemes did before trust anchors existed
			name: "a certificate without anchors",
			cfg:  plainScheme,
			args: []string{"--key=" + leafFile},
			mode: ModeKey,
			leaf: true,
		},
		{
			name:   "a certificate with anchors",
			cfg:    plainScheme,
			args:   []string{"--key=" + leafFile, "--trust-anchors=" + caFile},
			mode:   ModeChain,
			source: SourceFiles,
			leaf:   true,
		},
		{
			name:   "the built-in anchors, by default",
			cfg:    builtinScheme,
			args:   []string{"--key=" + leafFile},
			mode:   ModeChain,
			source: SourceBuiltin,
			leaf:   true,
		},
		{
			name:   "the built-in anchors, asked for by name",
			cfg:    builtinScheme,
			args:   []string{"--key=" + leafFile, "--trust-anchors=" + AnchorsBuiltin},
			mode:   ModeChain,
			source: SourceBuiltin,
			leaf:   true,
		},
		{
			// files displace the built-in anchors rather than adding
			// to them
			name:   "files in place of the built-in anchors",
			cfg:    builtinScheme,
			args:   []string{"--key=" + leafFile, "--trust-anchors=" + caFile},
			mode:   ModeChain,
			source: SourceFiles,
			leaf:   true,
		},
		{
			name: "skip-verify still loads the key",
			cfg:  plainScheme,
			args: []string{"--key=" + leafFile, "--skip-verify"},
			mode: ModeSkip,
			leaf: true,
		},
		{
			// nothing to anchor to when nothing is verified
			name: "skip-verify on a scheme with built-in anchors",
			cfg:  builtinScheme,
			args: []string{"--key=" + leafFile, "--skip-verify"},
			mode: ModeSkip,
			leaf: true,
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			v, err := options(t, tv.cfg, tv.args...).Resolve(testFs())
			require.NoError(t, err)

			assert.Equal(t, tv.mode, v.Mode)
			assert.Equal(t, tv.source, v.Source)

			if !tv.leaf {
				assert.Nil(t, v.Leaf)
				return
			}

			require.NotNil(t, v.Leaf)
			assert.Equal(t, leaf.Raw, v.Leaf.Raw)
			assert.Equal(t, leaf.PublicKey, v.Key)
		})
	}
}

func Test_Resolve_errors(t *testing.T) {
	for _, tv := range []struct {
		name     string
		cfg      VerifyConfig
		args     []string
		expected string
	}{
		{
			name:     "anchors with skip-verify",
			cfg:      plainScheme,
			args:     []string{"--key=" + leafFile, "--skip-verify", "--trust-anchors=" + caFile},
			expected: "--trust-anchors cannot be used with --skip-verify, which checks nothing",
		},
		{
			name:     "a CRL with skip-verify",
			cfg:      plainScheme,
			args:     []string{"--skip-verify", "--crl=" + crlFile},
			expected: "--crl cannot be used with --skip-verify",
		},
		{
			name:     "a CRL policy with skip-verify",
			cfg:      plainScheme,
			args:     []string{"--skip-verify", "--crl-policy=permissive"},
			expected: "--crl-policy cannot be used with --skip-verify",
		},
		{
			name:     "a CRL policy without a CRL",
			cfg:      plainScheme,
			args:     []string{"--key=" + leafFile, "--crl-policy=permissive"},
			expected: "--crl-policy only applies to a revocation list, so it needs --crl",
		},
		{
			name: "an unknown CRL policy",
			cfg:  plainScheme,
			args: []string{"--key=" + leafFile, "--trust-anchors=" + caFile,
				"--crl=" + crlFile, "--crl-policy=lenient"},
			expected: `unknown --crl-policy "lenient": expected strict or permissive`,
		},
		{
			name:     "a CRL without anchors",
			cfg:      plainScheme,
			args:     []string{"--key=" + leafFile, "--crl=" + crlFile},
			expected: "--crl is checked against a certificate chain, so it needs --trust-anchors",
		},
		{
			name:     "built-in anchors a scheme does not have",
			cfg:      plainScheme,
			args:     []string{"--key=" + leafFile, "--trust-anchors=" + AnchorsBuiltin},
			expected: "this scheme has no built-in trust anchors, so name a file",
		},
		{
			// the two anchor sets are alternatives, and merging them
			// silently would widen the trust the caller asked for
			name: "built-in anchors mixed with files",
			cfg:  builtinScheme,
			args: []string{"--key=" + leafFile,
				"--trust-anchors=" + AnchorsBuiltin, "--trust-anchors=" + caFile},
			expected: "cannot be combined with anchor files",
		},
		{
			name:     "anchors for a bare key",
			cfg:      plainScheme,
			args:     []string{"--key=" + keyFile, "--trust-anchors=" + caFile},
			expected: "--key has to name a certificate",
		},
		{
			name:     "an absent key",
			cfg:      plainScheme,
			args:     []string{"--key=absent.pem"},
			expected: "error loading key from absent.pem",
		},
		{
			name:     "an absent anchor",
			cfg:      plainScheme,
			args:     []string{"--key=" + leafFile, "--trust-anchors=absent.pem"},
			expected: "loading trust anchor from absent.pem",
		},
		{
			name:     "an absent CRL",
			cfg:      plainScheme,
			args:     []string{"--key=" + leafFile, "--trust-anchors=" + caFile, "--crl=absent.crl"},
			expected: "loading CRL from absent.crl",
		},
		{
			name:     "a certificate in place of a CRL",
			cfg:      plainScheme,
			args:     []string{"--key=" + leafFile, "--trust-anchors=" + caFile, "--crl=" + caFile},
			expected: "parsing CRL from " + caFile,
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			_, err := options(t, tv.cfg, tv.args...).Resolve(testFs())
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

func Test_VerifyLeaf(t *testing.T) {
	for _, tv := range []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name: "a chain to its anchor",
			args: []string{"--key=" + leafFile, "--trust-anchors=" + caFile},
		},
		{
			name:     "a chain to an anchor that did not issue it",
			args:     []string{"--key=" + leafFile, "--trust-anchors=" + otherCAFile},
			expected: "error verifying the certificate chain",
		},
		{
			name: "a CRL revoking nothing",
			args: []string{"--key=" + leafFile, "--trust-anchors=" + caFile, "--crl=" + crlFile},
		},
		{
			name:     "a CRL revoking the leaf",
			args:     []string{"--key=" + leafFile, "--trust-anchors=" + caFile, "--crl=" + revokingCRL},
			expected: `certificate "CN=gen-corim test IAK" is revoked`,
		},
		{
			name:     "no CRL covers the issuer, strictly",
			args:     []string{"--key=" + leafFile, "--trust-anchors=" + caFile, "--crl=" + unrelatedCRL},
			expected: "no CRL covers the issuer",
		},
		{
			name: "no CRL covers the issuer, permissively",
			args: []string{"--key=" + leafFile, "--trust-anchors=" + caFile,
				"--crl=" + unrelatedCRL, "--crl-policy=permissive"},
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			v, err := options(t, plainScheme, tv.args...).Resolve(testFs())
			require.NoError(t, err)

			err = v.VerifyLeaf(testNow)

			if tv.expected == "" {
				assert.NoError(t, err)
				return
			}

			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

// The OS trust store is what both crypto/x509 and corim fall back on for a nil
// pool, and it has no business vouching for attestation keys. VerifyLeaf has to
// refuse rather than reach it, however it is called.
func Test_VerifyLeaf_never_reaches_the_os_trust_store(t *testing.T) {
	leaf := certificate(t, leafFile)

	for _, tv := range []struct {
		name string
		v    *Verifier
	}{
		{
			name: "a nil pool",
			v:    &Verifier{Mode: ModeChain, Source: SourceFiles, Leaf: leaf},
		},
		{
			name: "built-in anchors, which only the scheme can apply",
			v:    &Verifier{Mode: ModeChain, Source: SourceBuiltin, Leaf: leaf},
		},
		{
			name: "a key that was never meant to be chained",
			v:    &Verifier{Mode: ModeKey, Leaf: leaf},
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			assert.ErrorContains(t, tv.v.VerifyLeaf(testNow), "internal error")
		})
	}

	// The built-in source resolves to no pool, so the guard above is the
	// one a scheme with built-in anchors would meet.
	v, err := options(t, builtinScheme, "--key="+leafFile).Resolve(testFs())
	require.NoError(t, err)
	assert.Nil(t, v.pool)
}

// The fixture lists are current, so the rules that turn on time are checked
// against a chosen instant rather than against a fixture minted to be stale.
func Test_CheckCRLValidity(t *testing.T) {
	v, err := options(t, plainScheme, "--key="+leafFile, "--trust-anchors="+caFile, "--crl="+crlFile).
		Resolve(testFs())
	require.NoError(t, err)

	crls, _ := v.CRLs()
	require.Len(t, crls, 1)

	crl := crls[0]

	assert.NoError(t, CheckCRLValidity(crl, testNow, corim.CrlPolicyStrict))
	assert.ErrorContains(t, CheckCRLValidity(crl, crl.ThisUpdate.Add(-time.Hour), corim.CrlPolicyStrict),
		"is not valid yet")
	assert.ErrorContains(t, CheckCRLValidity(crl, crl.NextUpdate.Add(time.Hour), corim.CrlPolicyStrict),
		"has expired")

	// A list that never expires cannot stand in for a current one, which is
	// the difference the strict policy makes.
	endless := *crl
	endless.NextUpdate = time.Time{}

	assert.ErrorContains(t, CheckCRLValidity(&endless, testNow, corim.CrlPolicyStrict), "has no nextUpdate")
	assert.NoError(t, CheckCRLValidity(&endless, testNow, corim.CrlPolicyPermissive))
}

func Test_CRLs(t *testing.T) {
	for _, tv := range []struct {
		name   string
		args   []string
		count  int
		policy corim.CrlPolicy
	}{
		{
			name:   "none",
			args:   []string{"--key=" + leafFile, "--trust-anchors=" + caFile},
			policy: corim.CrlPolicyStrict,
		},
		{
			name:   "one, strictly by default",
			args:   []string{"--key=" + leafFile, "--trust-anchors=" + caFile, "--crl=" + crlFile},
			count:  1,
			policy: corim.CrlPolicyStrict,
		},
		{
			name: "one, permissively",
			args: []string{"--key=" + leafFile, "--trust-anchors=" + caFile,
				"--crl=" + crlFile, "--crl-policy=permissive"},
			count:  1,
			policy: corim.CrlPolicyPermissive,
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			v, err := options(t, plainScheme, tv.args...).Resolve(testFs())
			require.NoError(t, err)

			crls, policy := v.CRLs()
			assert.Len(t, crls, tv.count)
			assert.Equal(t, tv.policy, policy)
		})
	}
}

func Test_CRLsSignedBy(t *testing.T) {
	v, err := options(t, plainScheme, "--key="+leafFile, "--trust-anchors="+caFile,
		"--crl="+crlFile, "--crl="+unrelatedCRL).Resolve(testFs())
	require.NoError(t, err)

	crls, _ := v.CRLs()
	require.Len(t, crls, 2)

	assert.Len(t, CRLsSignedBy(crls, certificate(t, caFile)), 1)
	assert.Len(t, CRLsSignedBy(crls, certificate(t, otherCAFile)), 1)
	assert.Empty(t, CRLsSignedBy(crls, certificate(t, intermediateCA)))
	assert.Empty(t, CRLsSignedBy(append(crls, nil), certificate(t, leafFile)))
}

// A chain file holding several certificates is what a key distribution service
// publishes, and every anchor in it has to be trusted.
func Test_Resolve_chain_file(t *testing.T) {
	v, err := options(t, plainScheme, "--key="+leafFile, "--trust-anchors="+certChainFile).Resolve(testFs())
	require.NoError(t, err)

	assert.Equal(t, ModeChain, v.Mode)
	assert.NoError(t, v.VerifyLeaf(testNow))
}
