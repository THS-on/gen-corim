// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package keyutil loads the public keys used to verify evidence and to populate
// the attestation verification key triples of the generated CoRIM.
package keyutil

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/afero"
	"github.com/veraison/corim/comid"
)

const certPEMBlock = "CERTIFICATE"

// PublicKeyFromFile loads a public key from the named file, which may hold a
// JSON Web Key, PEM-encoded data or a raw DER PKIX public key.
func PublicKeyFromFile(fs afero.Fs, path string) (crypto.PublicKey, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("error loading key from %s: %w", path, err)
	}

	pk, err := PublicKeyFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("error loading key from %s: %w", path, err)
	}

	return pk, nil
}

// PublicKeyFromBytes extracts a public key from the supplied JWK, PEM or raw
// DER PKIX data. A private key is accepted as a JWK or PEM, in which case the
// corresponding public key is returned.
//
// Note that corim.NewPublicKeyFromJWK is not used here: it obtains the public
// key from a crypto.Signer and so only accepts a private JWK, whereas the key
// used to verify evidence is normally distributed in its public form alone.
func PublicKeyFromBytes(data []byte) (crypto.PublicKey, error) {
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		return publicKeyFromPEM(data)
	}

	if json.Valid(data) {
		return publicKeyFromJWK(data)
	}

	return x509.ParsePKIXPublicKey(data)
}

// CertificateFromFile loads an X.509 certificate from the named file, which may
// hold either PEM or raw DER.
func CertificateFromFile(fs afero.Fs, path string) (*x509.Certificate, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate from %s: %w", path, err)
	}

	cert, err := CertificateFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("error loading certificate from %s: %w", path, err)
	}

	return cert, nil
}

// CertificateFromBytes parses an X.509 certificate from the supplied PEM or raw
// DER data.
func CertificateFromBytes(data []byte) (*x509.Certificate, error) {
	if bytes.Contains(data, []byte("-----BEGIN ")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found")
		}

		if block.Type != certPEMBlock {
			return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
		}

		data = block.Bytes
	}

	return x509.ParseCertificate(data)
}

// CertificatesFromFile loads a chain of X.509 certificates from the named file,
// which may hold either concatenated PEM blocks or concatenated raw DER.
func CertificatesFromFile(fs afero.Fs, path string) ([]*x509.Certificate, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("error loading certificates from %s: %w", path, err)
	}

	if bytes.Contains(data, []byte("-----BEGIN ")) {
		if data, err = certDERFromPEM(data); err != nil {
			return nil, fmt.Errorf("error loading certificates from %s: %w", path, err)
		}
	}

	certs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("error loading certificates from %s: %w", path, err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("error loading certificates from %s: no certificate found", path)
	}

	return certs, nil
}

// KeyIDFromJWK returns the kid of the supplied JSON Web Key, or the empty
// string if it carries none.
func KeyIDFromJWK(data []byte) (string, error) {
	key, err := jwk.ParseKey(data)
	if err != nil {
		return "", err
	}

	return key.KeyID(), nil
}

// PKIXBase64Key converts a public key into the tagged-pkix-base64-key-type
// CryptoKey used by the attestation verification key triples.
func PKIXBase64Key(pk crypto.PublicKey) (*comid.CryptoKey, error) {
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}

	var buf bytes.Buffer

	if err = pem.Encode(&buf, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
		return nil, fmt.Errorf("error PEM encoding public key: %w", err)
	}

	key, err := comid.NewPKIXBase64Key(buf.String())
	if err != nil {
		return nil, fmt.Errorf("error creating verification key: %w", err)
	}

	return key, nil
}

// certDERFromPEM concatenates the bodies of the CERTIFICATE blocks in data, so
// that a PEM bundle can be parsed by the same call as a DER one.
func certDERFromPEM(data []byte) ([]byte, error) {
	var der []byte

	rest := data

	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block

		if block, rest = pem.Decode(rest); block == nil {
			return nil, fmt.Errorf("no PEM block found")
		}

		if block.Type != certPEMBlock {
			return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
		}

		der = append(der, block.Bytes...)
	}

	return der, nil
}

func publicKeyFromJWK(data []byte) (crypto.PublicKey, error) {
	var key any

	if err := jwk.ParseRawKey(data, &key); err != nil {
		return nil, err
	}

	return publicPart(key)
}

func publicKeyFromPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case certPEMBlock:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return publicPart(key)
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return publicPart(key)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// publicPart returns the public half of a private key, or the key itself if it
// is already a public one.
func publicPart(key any) (crypto.PublicKey, error) {
	if key == nil {
		return nil, fmt.Errorf("no key found")
	}

	if private, ok := key.(interface{ Public() crypto.PublicKey }); ok {
		return private.Public(), nil
	}

	return key, nil
}
