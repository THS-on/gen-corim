//go:build ignore

// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Command generate mints the certificate fixtures in this directory. Run it
// from the root of the repository:
//
//	go run data/certs/generate.go
//
// The certificates are generated rather than captured: no attestation scheme
// publishes an IAK or CPAK certificate to take one from. They certify the
// public keys the token vectors were really signed with, so a chain to them
// verifies a real token, and they are dated far enough out that the tests do
// not start failing on a date.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
	"github.com/veraison/gen-corim/keyutil"
)

const dir = "data/certs"

var (
	notBefore = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2046, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// Fixed so that a regenerated fixture keeps the identity the tests refer to.
const (
	serialCA           = 1
	serialOtherCA      = 2
	serialIntermediate = 3
	serialIAK          = 4
	serialCPAK         = 5
)

type authority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newAuthority(name string, serial int64) *authority {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generating a key for %s: %v", name, err)
	}

	return &authority{key: key, cert: sign(caTemplate(name, serial), nil, key.Public(), key)}
}

// issueCA certifies a subordinate authority, which stands in for an
// intermediate signing key such as AMD's ASK.
func (a *authority) issueCA(name string, serial int64) *authority {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generating a key for %s: %v", name, err)
	}

	return &authority{key: key, cert: sign(caTemplate(name, serial), a, key.Public(), a.key)}
}

// issueFor certifies a public key whose private half we do not hold - the key a
// token vector was signed with.
func (a *authority) issueFor(name string, serial int64, pk crypto.PublicKey) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	return sign(template, a, pk, a.key)
}

func (a *authority) crl(revoked ...*x509.Certificate) []byte {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, cert := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: notBefore,
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                notBefore,
		NextUpdate:                notAfter,
		RevokedCertificateEntries: entries,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, a.cert, a.key)
	if err != nil {
		log.Fatalf("creating a CRL for %s: %v", a.cert.Subject, err)
	}

	return der
}

func caTemplate(name string, serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
}

func sign(template *x509.Certificate, issuer *authority, pk crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	parent := template
	if issuer != nil {
		parent = issuer.cert
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, pk, signer)
	if err != nil {
		log.Fatalf("signing %s: %v", template.Subject, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatalf("parsing %s: %v", template.Subject, err)
	}

	return cert
}

func write(name, blockType string, der []byte) {
	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0644); err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}

	fmt.Println("wrote", path)
}

func publicKey(path string) crypto.PublicKey {
	pk, err := keyutil.PublicKeyFromFile(afero.NewOsFs(), path)
	if err != nil {
		log.Fatal(err)
	}

	return pk
}

func main() {
	if _, err := os.Stat(dir); err != nil {
		log.Fatalf("run this from the root of the repository: %v", err)
	}

	ca := newAuthority("gen-corim test CA", serialCA)
	other := newAuthority("gen-corim other test CA", serialOtherCA)
	intermediate := ca.issueCA("gen-corim test intermediate CA", serialIntermediate)

	iak := ca.issueFor("gen-corim test IAK", serialIAK, publicKey("data/keys/es256-pub.json"))
	cpak := ca.issueFor("gen-corim test CPAK", serialCPAK, publicKey("data/cca/tf-rmm/cca_platform.pub"))

	write("ca.pem", "CERTIFICATE", ca.cert.Raw)
	write("other-ca.pem", "CERTIFICATE", other.cert.Raw)
	write("intermediate.pem", "CERTIFICATE", intermediate.cert.Raw)
	write("iak.pem", "CERTIFICATE", iak.Raw)
	write("cpak.pem", "CERTIFICATE", cpak.Raw)

	write("crl.pem", "X509 CRL", ca.crl())
	write("crl-revoked.pem", "X509 CRL", ca.crl(iak, cpak))
	write("other-crl.pem", "X509 CRL", other.crl())

	// The chain as a key distribution service publishes one: the
	// intermediate first, then the root that signed it.
	chain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...,
	)

	path := filepath.Join(dir, "cert-chain.pem")
	if err := os.WriteFile(path, chain, 0644); err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}

	fmt.Println("wrote", path)
}
