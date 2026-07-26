// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/spf13/afero"
	"github.com/veraison/corim/corim"
	"github.com/veraison/gen-corim/keyutil"
	"github.com/veraison/gen-corim/scheme"
)

// vlekBundles are the AS[V]K and ARK certificates AMD publishes for VLEK
// endorsement keys. go-sev-guest embeds them but installs only the VCEK ones in
// its default roots, so a VLEK-signed report has nothing to verify against
// unless they are wired up here.
var vlekBundles = map[string][]byte{
	"Milan": trust.AskArkMilanVlekBytes,
	"Genoa": trust.AskArkGenoaVlekBytes,
	"Turin": trust.AskArkTurinVlekBytes,
}

// noNetwork refuses every fetch go-sev-guest might attempt. Certificate and
// revocation list retrieval are already disabled by the options below; this
// makes the absence of network access a property of the code rather than of the
// way it is called.
type noNetwork struct{}

func (noNetwork) Get(url string) ([]byte, error) {
	return nil, fmt.Errorf("refusing to fetch %s: gen-corim makes no network calls", url)
}

// decodeReport reads the report, and the certificate table an extended report
// carries after it. A bare report has none, and asking go-sev-guest for one
// anyway makes it complain to stderr.
func decodeReport(raw []byte) (*sevsnp.Report, *sevsnp.CertificateChain, error) {
	if len(raw) <= abi.ReportSize {
		report, err := abi.ReportToProto(raw)

		return report, nil, err
	}

	attestation, err := abi.ReportCertsToProto(raw)
	if err != nil {
		return nil, nil, err
	}

	return attestation.GetReport(), attestation.GetCertificateChain(), nil
}

// endorsementCert is the V[CL]EK the report was signed with. It comes from
// --key, or from the certificate table of an extended report; a report carrying
// one that --key contradicts is an error rather than a choice to make silently.
func endorsementCert(
	v *scheme.Verifier, chain *sevsnp.CertificateChain, reportFile string,
) (*x509.Certificate, error) {
	fromReport, err := chainCert(chain)
	if err != nil {
		return nil, fmt.Errorf("error reading the certificate table of %s: %w", reportFile, err)
	}

	switch {
	case v.Leaf == nil && fromReport == nil:
		return nil, errors.New(
			"no certificate supplied: the report carries none, so use --key, " +
				"or --skip-verify to generate from an unverified report")
	case v.Leaf == nil:
		return fromReport, nil
	case fromReport == nil || bytes.Equal(v.Leaf.Raw, fromReport.Raw):
		return v.Leaf, nil
	default:
		return nil, fmt.Errorf(
			"the certificate in --key is not the one %s carries: one of the two is for another report",
			reportFile)
	}
}

func chainCert(chain *sevsnp.CertificateChain) (*x509.Certificate, error) {
	der := chain.GetVcekCert()
	if len(der) == 0 {
		der = chain.GetVlekCert()
	}

	if len(der) == 0 {
		return nil, nil
	}

	return x509.ParseCertificate(der)
}

// verifyReport checks the report signature against the endorsement certificate.
// In chain mode the certificate is checked too, against AMD's trust anchors:
// that it is a KDS-issued V[CL]EK of the right shape, currently valid, and
// certified by the ASK and ARK of its product line.
func (o *Scheme) verifyReport(
	fs afero.Fs, v *scheme.Verifier, raw []byte, report *sevsnp.Report, cert *x509.Certificate,
) error {
	if v.Mode != scheme.ModeChain {
		return verify.SnpReportSignature(raw, cert)
	}

	info, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return fmt.Errorf("error parsing the signer info: %w", err)
	}

	root, err := o.trustedRoots(fs, v, report, cert, info.SigningKey)
	if err != nil {
		return err
	}

	opts := &verify.Options{
		DisableCertFetching: true,
		Getter:              noNetwork{},
		Now:                 time.Now(),
	}

	if root != nil {
		if err := applyCRLs(v, opts, root); err != nil {
			return err
		}

		opts.TrustedRoots = map[string][]*trust.AMDRootCerts{root.GetProductLine(): {root}}
	}

	return verify.SnpAttestation(attestation(report, cert, info.SigningKey), opts)
}

func attestation(report *sevsnp.Report, cert *x509.Certificate, signer abi.ReportSigner) *sevsnp.Attestation {
	chain := &sevsnp.CertificateChain{}

	if signer == abi.VlekReportSigner {
		chain.VlekCert = cert.Raw
	} else {
		chain.VcekCert = cert.Raw
	}

	return &sevsnp.Attestation{Report: report, CertificateChain: chain}
}

// productLine is the CPU generation whose trust anchors apply. A v3 report names
// it outright; before that it is only in the endorsement certificate.
func productLine(report *sevsnp.Report, cert *x509.Certificate, signer abi.ReportSigner) (string, error) {
	if fms := report.GetCpuid1EaxFms(); fms != 0 {
		return kds.ProductLineFromFms(fms), nil
	}

	exts, err := kds.CertificateExtensions(cert, signer)
	if err != nil {
		return "", fmt.Errorf("error reading the KDS extensions of the certificate: %w", err)
	}

	product, err := kds.ParseProductName(exts.ProductName, signer)
	if err != nil {
		return "", fmt.Errorf("error reading the product name of the certificate: %w", err)
	}

	return kds.ProductLine(product), nil
}

// trustedRoots is the ASK and ARK the endorsement certificate has to chain to.
// It returns nil where go-sev-guest's own embedded roots serve, which is every
// VCEK-signed report with no revocation list to hang off them. Reading the
// product line is left until a root has to be picked, so that a malformed
// certificate is reported by go-sev-guest, which says more about it than we do.
func (o *Scheme) trustedRoots(
	fs afero.Fs, v *scheme.Verifier, report *sevsnp.Report, cert *x509.Certificate, signer abi.ReportSigner,
) (*trust.AMDRootCerts, error) {
	crls, _ := v.CRLs()

	if v.Source != scheme.SourceFiles && signer != abi.VlekReportSigner && len(crls) == 0 {
		return nil, nil
	}

	line, err := productLine(report, cert, signer)
	if err != nil {
		return nil, err
	}

	if v.Source == scheme.SourceFiles {
		return o.rootsFromFiles(fs, line)
	}

	if signer == abi.VlekReportSigner {
		return vlekRoots(line)
	}

	// The revocation list is checked against a root, so the embedded one has
	// to be named rather than left to go-sev-guest to find.
	root, err := trust.GetDefaultRootCerts(line)
	if err != nil {
		return nil, fmt.Errorf("%w: supply them with --trust-anchors", err)
	}

	return root, nil
}

func vlekRoots(line string) (*trust.AMDRootCerts, error) {
	bundle, ok := vlekBundles[line]
	if !ok {
		return nil, fmt.Errorf("no built-in VLEK trust anchors for %s: supply them with --trust-anchors", line)
	}

	root := trust.AMDRootCertsProduct(line)
	if err := root.FromKDSCertBytes(bundle); err != nil {
		return nil, fmt.Errorf("error reading the built-in VLEK trust anchors for %s: %w", line, err)
	}

	return root, nil
}

// rootsFromFiles sorts the anchors --trust-anchors named into the roles
// go-sev-guest expects: the ARK is the one that signed itself, and the
// intermediate is an ASVK where it names itself one and an ASK otherwise, which
// is how go-sev-guest reads a KDS certificate chain.
func (o *Scheme) rootsFromFiles(fs afero.Fs, line string) (*trust.AMDRootCerts, error) {
	root := trust.AMDRootCertsProduct(line)
	root.ProductCerts = &trust.ProductCerts{}

	for _, path := range o.AnchorFiles() {
		certs, err := keyutil.CertificatesFromFile(fs, path)
		if err != nil {
			return nil, err
		}

		for _, cert := range certs {
			switch {
			case cert.CheckSignatureFrom(cert) == nil:
				root.ProductCerts.Ark = cert
			case strings.HasPrefix(cert.Subject.CommonName, "SEV-VLEK"):
				root.ProductCerts.Asvk = cert
			default:
				root.ProductCerts.Ask = cert
			}
		}
	}

	if root.ProductCerts.Ark == nil {
		return nil, fmt.Errorf("--trust-anchors names no AMD root key: expected a self-signed ARK for %s", line)
	}

	if root.ProductCerts.Ask == nil && root.ProductCerts.Asvk == nil {
		return nil, fmt.Errorf("--trust-anchors names no AMD signing key: expected an ASK or ASVK for %s", line)
	}

	return root, nil
}

// applyCRLs hands go-sev-guest the revocation list --crl named, checked against
// the time already in opts. It only ever checks the ASK against a list the ARK
// signed - AMD supersede a VCEK by its TCB version rather than revoking it - and
// it fetches one itself unless the list it is given is current, which is why an
// unusable list is an error here.
func applyCRLs(v *scheme.Verifier, opts *verify.Options, root *trust.AMDRootCerts) error {
	crls, policy := v.CRLs()
	if len(crls) == 0 {
		return nil
	}

	matched := scheme.CRLsSignedBy(crls, root.ProductCerts.Ark)
	if len(matched) == 0 {
		if policy == corim.CrlPolicyPermissive {
			return nil
		}

		return fmt.Errorf("no CRL covers the AMD root key of %s", root.GetProductLine())
	}

	// A list that matches but cannot be used fails under either policy, as it
	// does for a signed CoRIM's x5chain.
	var lastErr error

	for _, crl := range matched {
		if lastErr = scheme.CheckCRLValidity(crl, opts.Now, policy); lastErr != nil {
			continue
		}

		root.CRL = crl
		opts.CheckRevocations = true

		return nil
	}

	return lastErr
}
