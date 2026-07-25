// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
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

// testChain is a certificate chain, the leaf of which certifies the public
// half of testSigningKey.
type testChain struct {
	leaf         *x509.Certificate
	intermediate *x509.Certificate
	root         *x509.Certificate
	// other is a leaf certifying a key that is not testSigningKey.
	other *x509.Certificate
}

// newTestChain issues root -> intermediate -> leaf, the leaf carrying the
// public half of testSigningKey so that it matches the CoRIM signature.
func newTestChain(t *testing.T) *testChain {
	t.Helper()

	var signingKey ecdsa.PrivateKey
	require.NoError(t, jwk.ParseRawKey(testSigningKey, &signingKey))

	rootKey := newTestKey(t)
	intermediateKey := newTestKey(t)

	root := issue(t, "root", true, rootKey.Public(), rootKey, nil)
	intermediate := issue(t, "intermediate", true, intermediateKey.Public(), rootKey, root)

	return &testChain{
		leaf:         issue(t, "leaf", false, signingKey.Public(), intermediateKey, intermediate),
		intermediate: intermediate,
		root:         root,
		other:        issue(t, "other", false, newTestKey(t).Public(), intermediateKey, intermediate),
	}
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}

// issue creates a certificate for pub, signed by issuerKey. A nil parent makes
// it self-signed.
func issue(
	t *testing.T,
	cn string,
	isCA bool,
	pub crypto.PublicKey,
	issuerKey *ecdsa.PrivateKey,
	parent *x509.Certificate,
) *x509.Certificate {
	t.Helper()

	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
	}

	if parent == nil {
		parent = tmpl
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, issuerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// writeDER writes the concatenated DER of the supplied certificates to path.
func writeDER(t *testing.T, fs afero.Fs, path string, certs ...*x509.Certificate) {
	t.Helper()

	var der []byte
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}

	require.NoError(t, afero.WriteFile(fs, path, der, 0644))
}

// writePEM writes the supplied certificates to path as concatenated PEM blocks.
func writePEM(t *testing.T, fs afero.Fs, path string, certs ...*x509.Certificate) {
	t.Helper()

	var buf []byte
	for _, cert := range certs {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	require.NoError(t, afero.WriteFile(fs, path, buf, 0644))
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
