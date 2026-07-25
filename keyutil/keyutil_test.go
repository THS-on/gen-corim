// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package keyutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
)

const (
	// testPrivateJWK carries a "d" parameter, so parsing it yields a private
	// key that has to be reduced to its public half.
	testPrivateJWK = "../data/keys/es256-priv.json"
	// testPublicJWK is the public half of testPrivateJWK.
	testPublicJWK = "../data/keys/es256-pub.json"
	// testWrongJWK is an unrelated key.
	testWrongJWK = "../data/keys/wrong-es256.json"
)

func osFs() afero.Fs { return afero.NewOsFs() }

// privateKeyFromJWK loads the private key held in a JWK file, so that tests can
// re-encode it in the PEM forms the loader is expected to accept.
func privateKeyFromJWK(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()

	data, err := afero.ReadFile(osFs(), path)
	require.NoError(t, err)

	var key any
	require.NoError(t, jwk.ParseRawKey(data, &key))

	private, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok, "%s should hold an EC private key", path)

	return private
}

func pemBlock(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, pem.Encode(&buf, &pem.Block{Type: blockType, Bytes: der}))

	return buf.Bytes()
}

// testCertificate returns a self-signed certificate over testPrivateJWK and its
// DER encoding, so that the loaders can be exercised without carrying a vector.
func testCertificate(t *testing.T) (cert *x509.Certificate, der []byte) {
	t.Helper()

	key := privateKeyFromJWK(t, testPrivateJWK)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gen-corim test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, der
}

// The private and public vectors are one key pair, so both must yield the same
// public key; the third is unrelated, and pins that they are really compared.
func Test_PublicKeyFromFile_jwk(t *testing.T) {
	fromPrivate, err := PublicKeyFromFile(osFs(), testPrivateJWK)
	require.NoError(t, err)

	fromPublic, err := PublicKeyFromFile(osFs(), testPublicJWK)
	require.NoError(t, err)

	wrong, err := PublicKeyFromFile(osFs(), testWrongJWK)
	require.NoError(t, err)

	assert.True(t, fromPrivate.(*ecdsa.PublicKey).Equal(fromPublic))
	assert.False(t, fromPrivate.(*ecdsa.PublicKey).Equal(wrong))
}

func Test_PublicKeyFromFile_absent(t *testing.T) {
	_, err := PublicKeyFromFile(osFs(), "../data/keys/absent.json")
	assert.ErrorContains(t, err, "error loading key from ../data/keys/absent.json")
}

// Every PEM form the loader accepts has to reduce to the same public key,
// whether it carries the public half, a private key or a certificate.
func Test_PublicKeyFromBytes_pem_forms(t *testing.T) {
	private := privateKeyFromJWK(t, testPrivateJWK)
	expected := private.Public().(*ecdsa.PublicKey)

	pkixDER, err := x509.MarshalPKIXPublicKey(expected)
	require.NoError(t, err)

	sec1DER, err := x509.MarshalECPrivateKey(private)
	require.NoError(t, err)

	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)

	_, certDER := testCertificate(t)

	for _, tv := range []struct {
		blockType string
		der       []byte
	}{
		{"PUBLIC KEY", pkixDER},
		{"EC PRIVATE KEY", sec1DER},
		{"PRIVATE KEY", pkcs8DER},
		{"CERTIFICATE", certDER},
	} {
		t.Run(tv.blockType, func(t *testing.T) {
			pk, err := PublicKeyFromBytes(pemBlock(t, tv.blockType, tv.der))
			require.NoError(t, err)
			assert.True(t, expected.Equal(pk))
		})
	}
}

func Test_PublicKeyFromBytes_der(t *testing.T) {
	expected := privateKeyFromJWK(t, testPrivateJWK).Public().(*ecdsa.PublicKey)

	der, err := x509.MarshalPKIXPublicKey(expected)
	require.NoError(t, err)

	pk, err := PublicKeyFromBytes(der)
	require.NoError(t, err)
	assert.True(t, expected.Equal(pk))
}

func Test_PublicKeyFromBytes_errors(t *testing.T) {
	for _, tv := range []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "not a key",
			data:     []byte("{}"),
			expected: "failed to parse key",
		},
		{
			name:     "neither JSON nor DER",
			data:     []byte("not a key"),
			expected: "asn1: structure error",
		},
		{
			name:     "no PEM block",
			data:     []byte("-----BEGIN PUBLIC KEY-----\nnot base64\n"),
			expected: "no PEM block found",
		},
		{
			name:     "unsupported block type",
			data:     pemBlock(t, "DH PARAMETERS", []byte{1, 2, 3}),
			expected: `unsupported PEM block type "DH PARAMETERS"`,
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			_, err := PublicKeyFromBytes(tv.data)
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

// Both encodings a certificate is handed out in must load to the same one.
func Test_CertificateFromFile(t *testing.T) {
	cert, der := testCertificate(t)

	for _, tv := range []struct {
		name string
		data []byte
	}{
		{"der", der},
		{"pem", pemBlock(t, "CERTIFICATE", der)},
	} {
		t.Run(tv.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(fs, "cert", tv.data, 0644))

			loaded, err := CertificateFromFile(fs, "cert")
			require.NoError(t, err)
			assert.True(t, loaded.Equal(cert))
		})
	}
}

func Test_CertificateFromFile_errors(t *testing.T) {
	pk, err := x509.MarshalPKIXPublicKey(privateKeyFromJWK(t, testPrivateJWK).Public())
	require.NoError(t, err)

	for _, tv := range []struct {
		name string
		// data is written to the file under test, unless it is nil.
		data     []byte
		expected string
	}{
		{
			name:     "absent",
			expected: "error loading certificate from cert",
		},
		{
			name:     "no PEM block",
			data:     []byte("-----BEGIN CERTIFICATE-----\nnot base64\n"),
			expected: "error loading certificate from cert: no PEM block found",
		},
		{
			// a public key is not a certificate, and has to be
			// reported as such rather than silently misread
			name:     "public key",
			data:     pemBlock(t, "PUBLIC KEY", pk),
			expected: `unsupported PEM block type "PUBLIC KEY"`,
		},
		{
			name:     "not a certificate",
			data:     []byte{1, 2, 3, 4},
			expected: "error loading certificate from cert",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			fs := afero.NewMemMapFs()

			if tv.data != nil {
				require.NoError(t, afero.WriteFile(fs, "cert", tv.data, 0644))
			}

			_, err := CertificateFromFile(fs, "cert")
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

func Test_PKIXBase64Key(t *testing.T) {
	pk, err := PublicKeyFromFile(osFs(), testPrivateJWK)
	require.NoError(t, err)

	key, err := PKIXBase64Key(pk)
	require.NoError(t, err)

	assert.Equal(t, comid.PKIXBase64KeyType, key.Type())

	// the key must round-trip back to the one it was built from
	back, err := PublicKeyFromBytes([]byte(key.String()))
	require.NoError(t, err)
	assert.True(t, pk.(*ecdsa.PublicKey).Equal(back))

	_, err = PKIXBase64Key("not a key")
	assert.ErrorContains(t, err, "error marshaling public key")
}
