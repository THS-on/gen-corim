// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package scheme

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/veraison/corim/corim"
	"github.com/veraison/gen-corim/keyutil"
)

// AnchorsBuiltin is the reserved --trust-anchors value naming the trust anchors
// the evidence format defines for itself. A file of that name is reachable as
// ./builtin.
const AnchorsBuiltin = "builtin"

const (
	crlPolicyStrict     = "strict"
	crlPolicyPermissive = "permissive"
)

// Mode is what a scheme has been asked to do with the key it was given.
type Mode int

const (
	// ModeSkip is --skip-verify: the evidence signature is not checked.
	ModeSkip Mode = iota
	// ModeKey checks the signature against a public key, which may be the
	// key of a certificate whose chain is not validated.
	ModeKey
	// ModeChain validates the certificate to its trust anchors before its
	// key is used.
	ModeChain
)

// AnchorSource is where the trust anchors of a ModeChain verification come from.
type AnchorSource int

const (
	// SourceNone is the absence of anchors, which is every mode but
	// ModeChain.
	SourceNone AnchorSource = iota
	// SourceBuiltin is the anchor set the evidence format defines, which
	// only the scheme knows how to apply.
	SourceBuiltin
	// SourceFiles is the anchors named by --trust-anchors.
	SourceFiles
)

// VerifyConfig is what a scheme says about its own verification surface.
type VerifyConfig struct {
	// KeyUsage and SkipVerifyUsage are the help texts of --key and
	// --skip-verify, which name the key and the evidence of the scheme.
	KeyUsage        string
	SkipVerifyUsage string
	// HasBuiltinAnchors states that the format ships trust anchors of its
	// own, making them the default and AnchorsBuiltin a valid value.
	HasBuiltinAnchors bool
}

// VerifyOptions binds the flags that say how evidence is to be verified. A
// scheme embeds one, so the flags bind to the scheme receiver.
type VerifyOptions struct {
	cfg         VerifyConfig
	keyFile     string
	skipVerify  bool
	anchorFiles []string
	crlFiles    []string
	crlPolicy   string
}

func NewVerifyOptions(cfg VerifyConfig) VerifyOptions {
	return VerifyOptions{cfg: cfg}
}

// KeyFile is the path given to --key, empty when the flag was not used.
func (o *VerifyOptions) KeyFile() string { return o.keyFile }

func (o *VerifyOptions) SkipVerify() bool { return o.skipVerify }

func (o *VerifyOptions) AddFlags(flags *pflag.FlagSet) {
	flags.StringVarP(&o.keyFile, "key", "k", "", o.cfg.KeyUsage)
	flags.BoolVar(&o.skipVerify, "skip-verify", false, o.cfg.SkipVerifyUsage)
	flags.StringArrayVar(&o.anchorFiles, "trust-anchors", nil,
		o.anchorsUsage())
	flags.StringArrayVar(&o.crlFiles, "crl", nil,
		"certificate revocation list, in PEM or DER format, checked against the certificate chain")
	flags.StringVar(&o.crlPolicy, "crl-policy", "",
		"what to do when no --crl matches an issuer in the chain: strict, the default, fails and permissive skips")
}

func (o *VerifyOptions) anchorsUsage() string {
	usage := "trust anchors the certificate is verified against, in PEM or DER format"

	if o.cfg.HasBuiltinAnchors {
		return usage + `, or "` + AnchorsBuiltin + `" for the ones built in, which is the default`
	}

	return usage
}

// Valid checks the flag combinations that hold for every scheme. Whether a key
// is required at all is the scheme's own business.
func (o *VerifyOptions) Valid() error {
	if o.skipVerify {
		for _, tv := range []struct {
			flag string
			used bool
		}{
			{"--trust-anchors", len(o.anchorFiles) > 0},
			{"--crl", len(o.crlFiles) > 0},
			{"--crl-policy", o.crlPolicy != ""},
		} {
			if tv.used {
				return fmt.Errorf("%s cannot be used with --skip-verify, which checks nothing", tv.flag)
			}
		}
	}

	if o.crlPolicy != "" {
		if len(o.crlFiles) == 0 {
			return errors.New("--crl-policy only applies to a revocation list, so it needs --crl")
		}

		if o.crlPolicy != crlPolicyStrict && o.crlPolicy != crlPolicyPermissive {
			return fmt.Errorf("unknown --crl-policy %q: expected %s or %s",
				o.crlPolicy, crlPolicyStrict, crlPolicyPermissive)
		}
	}

	return o.validAnchors()
}

func (o *VerifyOptions) validAnchors() error {
	var builtin, files bool

	for _, anchor := range o.anchorFiles {
		if anchor == AnchorsBuiltin {
			builtin = true
			continue
		}

		files = true
	}

	if builtin && !o.cfg.HasBuiltinAnchors {
		return fmt.Errorf("--trust-anchors=%s: this scheme has no built-in trust anchors, so name a file",
			AnchorsBuiltin)
	}

	if builtin && files {
		return fmt.Errorf("--trust-anchors=%s cannot be combined with anchor files: one set of anchors or the other",
			AnchorsBuiltin)
	}

	// A revocation list on its own revokes nothing: it is checked against the
	// chain that the anchors establish.
	if len(o.crlFiles) > 0 && len(o.anchorFiles) == 0 && !o.cfg.HasBuiltinAnchors {
		return errors.New("--crl is checked against a certificate chain, so it needs --trust-anchors")
	}

	return nil
}

// Verifier is the resolved form of the verification flags: the mode to verify
// in, the key to verify with, and the trust material to verify against.
type Verifier struct {
	Mode   Mode
	Source AnchorSource
	Key    crypto.PublicKey
	// Leaf is the certificate --key named, nil when it held a bare key.
	Leaf   *x509.Certificate
	pool   *x509.CertPool
	crls   []*x509.RevocationList
	policy corim.CrlPolicy
}

// Resolve loads the key, the trust anchors and the revocation lists, and
// settles which mode the verification runs in.
func (o *VerifyOptions) Resolve(fs afero.Fs) (*Verifier, error) {
	if err := o.Valid(); err != nil {
		return nil, err
	}

	v := &Verifier{Mode: ModeKey, Source: SourceNone}

	if o.keyFile != "" {
		if err := v.loadKey(fs, o.keyFile); err != nil {
			return nil, err
		}
	}

	if err := o.loadTrustMaterial(fs, v); err != nil {
		return nil, err
	}

	if o.skipVerify {
		v.Mode = ModeSkip
		v.Source = SourceNone
	}

	return v, nil
}

func (o *Verifier) loadKey(fs afero.Fs, path string) error {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return fmt.Errorf("error loading key from %s: %w", path, err)
	}

	if cert, cerr := keyutil.CertificateFromBytes(data); cerr == nil {
		o.Leaf = cert
		o.Key = cert.PublicKey

		return nil
	}

	if o.Key, err = keyutil.PublicKeyFromBytes(data); err != nil {
		return fmt.Errorf("error loading key from %s: %w", path, err)
	}

	return nil
}

func (o *VerifyOptions) loadTrustMaterial(fs afero.Fs, v *Verifier) error {
	source := o.anchorSource()
	if source == SourceNone {
		return nil
	}

	// A leaf may also reach the scheme with the evidence, as an SNP report's
	// certificate table does, in which case --key is absent by design.
	if o.keyFile != "" && v.Leaf == nil {
		return errors.New(
			"--trust-anchors verifies a certificate chain, so --key has to name a certificate")
	}

	readFile := func(path string) ([]byte, error) { return afero.ReadFile(fs, path) }

	var anchorFiles []string
	if source == SourceFiles {
		anchorFiles = o.anchorFiles
	}

	anchors, err := corim.LoadTrustAnchors(readFile, anchorFiles, o.crlFiles)
	if err != nil {
		return err
	}

	v.Mode = ModeChain
	v.Source = source
	v.crls = anchors.CRLs
	v.policy = corim.CrlPolicyStrict

	if o.crlPolicy == crlPolicyPermissive {
		v.policy = corim.CrlPolicyPermissive
	}

	// A nil pool means the OS trust store to corim and to crypto/x509 alike,
	// which is never what a scheme here wants: the anchors of these formats
	// are published by their vendors, not by a browser root program.
	if source == SourceFiles {
		v.pool = anchors.Pool
	}

	return nil
}

func (o *VerifyOptions) anchorSource() AnchorSource {
	if len(o.anchorFiles) > 0 {
		if o.anchorFiles[0] == AnchorsBuiltin {
			return SourceBuiltin
		}

		return SourceFiles
	}

	if o.cfg.HasBuiltinAnchors && !o.skipVerify {
		return SourceBuiltin
	}

	return SourceNone
}

// CRLs returns the revocation lists --crl named and the policy to apply them
// under, for a scheme that validates the chain itself.
func (o *Verifier) CRLs() ([]*x509.RevocationList, corim.CrlPolicy) {
	return o.crls, o.policy
}

// VerifyLeaf validates the certificate against the anchors of --trust-anchors
// and, where a revocation list covers an issuer in the chain, against that.
// Built-in anchors are the scheme's own to apply.
func (o *Verifier) VerifyLeaf(now time.Time) error {
	if o.Mode != ModeChain || o.Source != SourceFiles {
		return errors.New("internal error: no trust anchors were loaded to verify against")
	}

	if o.pool == nil {
		// Both x509.VerifyOptions and corim.TrustAnchors read a nil pool
		// as the OS trust store.
		return errors.New("internal error: refusing to verify against the OS trust store")
	}

	chains, err := o.Leaf.Verify(x509.VerifyOptions{
		Roots:       o.pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("error verifying the certificate chain: %w", err)
	}

	// Several anchors can certify one leaf; the certificate is good if any
	// one of the chains they form survives revocation.
	var lastErr error

	for _, chain := range chains {
		if lastErr = o.checkRevocation(chain, now); lastErr == nil {
			return nil
		}
	}

	return fmt.Errorf("error verifying the certificate chain: %w", lastErr)
}

// checkRevocation follows the semantics corim applies to a signed CoRIM's
// x5chain: an issuer no CRL covers fails under the strict policy and is skipped
// under the permissive one.
func (o *Verifier) checkRevocation(chain []*x509.Certificate, now time.Time) error {
	if len(o.crls) == 0 {
		return nil
	}

	for i := 0; i+1 < len(chain); i++ {
		cert := chain[i]

		issuerCRLs := CRLsSignedBy(o.crls, chain[i+1])
		if len(issuerCRLs) == 0 {
			if o.policy == corim.CrlPolicyPermissive {
				continue
			}

			return fmt.Errorf("no CRL covers the issuer of certificate %q", cert.Subject)
		}

		if err := checkAgainstCRLs(cert, issuerCRLs, now, o.policy); err != nil {
			return err
		}
	}

	return nil
}

// CRLsSignedBy returns the revocation lists issuer signed, which are the ones
// that may speak for the certificates it issued.
func CRLsSignedBy(crls []*x509.RevocationList, issuer *x509.Certificate) []*x509.RevocationList {
	matched := make([]*x509.RevocationList, 0, len(crls))

	for _, crl := range crls {
		if crl != nil && crl.CheckSignatureFrom(issuer) == nil {
			matched = append(matched, crl)
		}
	}

	return matched
}

func checkAgainstCRLs(
	cert *x509.Certificate, crls []*x509.RevocationList, now time.Time, policy corim.CrlPolicy,
) error {
	var (
		validityErr error
		usable      bool
	)

	for _, crl := range crls {
		if err := CheckCRLValidity(crl, now, policy); err != nil {
			validityErr = err
			continue
		}

		usable = true

		if isRevoked(cert.SerialNumber, crl) {
			return fmt.Errorf("certificate %q is revoked", cert.Subject)
		}
	}

	if !usable {
		return validityErr
	}

	return nil
}

// CheckCRLValidity reports whether a revocation list may be relied on at now.
// The strict policy also demands a nextUpdate, so that a list which never
// expires cannot stand in for a current one.
func CheckCRLValidity(crl *x509.RevocationList, now time.Time, policy corim.CrlPolicy) error {
	issuer := crl.Issuer.String()

	if !crl.ThisUpdate.IsZero() && now.Before(crl.ThisUpdate) {
		return fmt.Errorf("the CRL from %q is not valid yet", issuer)
	}

	if policy == corim.CrlPolicyStrict && crl.NextUpdate.IsZero() {
		return fmt.Errorf("the CRL from %q has no nextUpdate", issuer)
	}

	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return fmt.Errorf("the CRL from %q has expired", issuer)
	}

	return nil
}

func isRevoked(serial *big.Int, crl *x509.RevocationList) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}

	return false
}
