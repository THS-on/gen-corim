// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/gen-corim/keyutil"
	"github.com/veraison/gen-corim/scheme"
)

// The fixtures stand in for an AMD certificate chain: a self-signed root, as
// the ARK is, and an intermediate it issued, as the ASK is. Their key material
// is not AMD's, but the shape is what the anchors are sorted by. See
// data/PROVENANCE.md.
const (
	testRoot         = "../../data/certs/ca.pem"
	testIntermediate = "../../data/certs/intermediate.pem"
	testChain        = "../../data/certs/cert-chain.pem"
	testRootCRL      = "../../data/certs/crl.pem"
	testOtherCRL     = "../../data/certs/other-crl.pem"
)

// testNow sits inside the validity of every fixture, so that the tests do not
// depend on the day they run.
var testNow = time.Date(2030, time.June, 1, 0, 0, 0, 0, time.UTC)

func anchoredScheme(t *testing.T, args ...string) *Scheme {
	t.Helper()

	s := New()
	require.NoError(t, newFlagSet(t, s).Parse(args))

	return s.(*Scheme)
}

// The ARK and the ASK are told apart by their shape rather than by their file:
// a KDS cert_chain holds both, and either may arrive on its own.
func Test_rootsFromFiles(t *testing.T) {
	fs := afero.NewOsFs()

	t.Run("a chain holding both", func(t *testing.T) {
		o := anchoredScheme(t, "--key="+testRoot, "--trust-anchors="+testChain)

		roots, err := o.rootsFromFiles(fs, "Milan")
		require.NoError(t, err)

		assert.Equal(t, "gen-corim test CA", roots.ProductCerts.Ark.Subject.CommonName)
		assert.Equal(t, "gen-corim test intermediate CA", roots.ProductCerts.Ask.Subject.CommonName)
		assert.Nil(t, roots.ProductCerts.Asvk)
	})

	t.Run("one file each", func(t *testing.T) {
		o := anchoredScheme(t, "--key="+testRoot,
			"--trust-anchors="+testRoot, "--trust-anchors="+testIntermediate)

		roots, err := o.rootsFromFiles(fs, "Milan")
		require.NoError(t, err)

		assert.NotNil(t, roots.ProductCerts.Ark)
		assert.NotNil(t, roots.ProductCerts.Ask)
	})

	t.Run("without a root", func(t *testing.T) {
		o := anchoredScheme(t, "--key="+testRoot, "--trust-anchors="+testIntermediate)

		_, err := o.rootsFromFiles(fs, "Milan")
		assert.ErrorContains(t, err, "names no AMD root key")
	})

	t.Run("without a signing key", func(t *testing.T) {
		o := anchoredScheme(t, "--key="+testRoot, "--trust-anchors="+testRoot)

		_, err := o.rootsFromFiles(fs, "Milan")
		assert.ErrorContains(t, err, "names no AMD signing key")
	})

	t.Run("an absent file", func(t *testing.T) {
		o := anchoredScheme(t, "--key="+testRoot, "--trust-anchors="+filepath.Join(t.TempDir(), "absent.pem"))

		_, err := o.rootsFromFiles(fs, "Milan")
		assert.ErrorContains(t, err, "error loading certificates from")
	})
}

// go-sev-guest fetches a revocation list of its own unless it is given a
// current one, so a list that cannot be used has to stop the run rather than
// leave the check to the network.
func Test_applyCRLs(t *testing.T) {
	fs := afero.NewOsFs()

	ark, err := keyutil.CertificateFromFile(fs, testRoot)
	require.NoError(t, err)

	roots := trust.AMDRootCertsProduct("Milan")
	roots.ProductCerts = &trust.ProductCerts{Ark: ark}

	resolve := func(t *testing.T, args ...string) *scheme.Verifier {
		t.Helper()

		v, err := anchoredScheme(t, args...).Resolve(fs)
		require.NoError(t, err)

		return v
	}

	t.Run("a list the root signed", func(t *testing.T) {
		opts := &verify.Options{Now: testNow}
		v := resolve(t, "--key="+testRoot, "--crl="+testRootCRL)

		require.NoError(t, applyCRLs(v, opts, roots))
		assert.True(t, opts.CheckRevocations)
		assert.NotNil(t, roots.CRL)
	})

	t.Run("a list nothing in the chain signed", func(t *testing.T) {
		opts := &verify.Options{Now: testNow}
		v := resolve(t, "--key="+testRoot, "--crl="+testOtherCRL)

		assert.ErrorContains(t, applyCRLs(v, opts, roots), "no CRL covers the AMD root key of Milan")
		assert.False(t, opts.CheckRevocations)
	})

	t.Run("the same, permissively", func(t *testing.T) {
		opts := &verify.Options{Now: testNow}
		v := resolve(t, "--key="+testRoot, "--crl="+testOtherCRL, "--crl-policy=permissive")

		require.NoError(t, applyCRLs(v, opts, roots))
		assert.False(t, opts.CheckRevocations)
	})

	t.Run("no list at all", func(t *testing.T) {
		opts := &verify.Options{Now: testNow}
		v := resolve(t, "--key="+testRoot)

		require.NoError(t, applyCRLs(v, opts, roots))
		assert.False(t, opts.CheckRevocations)
	})
}
