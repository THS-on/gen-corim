// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package psa generates PSA endorsements from a PSA attestation token.
package psa

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/corim/comid"
	corimpsa "github.com/veraison/corim/profiles/psa"
	"github.com/veraison/gen-corim/keyutil"
	"github.com/veraison/gen-corim/scheme"
	"github.com/veraison/psatoken"
)

// Scheme generates a CoRIM carrying the reference values and the attestation
// verification key of a PSA attester.
type Scheme struct {
	scheme.VerifyOptions
}

// New returns a PSA scheme with its own flag state.
func New() scheme.Scheme {
	return &Scheme{
		VerifyOptions: scheme.NewVerifyOptions(scheme.VerifyConfig{
			KeyUsage:        "IAK public key or certificate, in JWK, PEM or DER format, used to verify the token",
			SkipVerifyUsage: "do not check the token signature",
		}),
	}
}

func (o *Scheme) Use() string { return "psa <token-file>" }

func (o *Scheme) Short() string { return "generate PSA endorsements from a PSA token" }

func (o *Scheme) Long() string {
	return `Generate PSA endorsements from a PSA attestation token.

The software components of the token become the reference values of the
generated CoRIM, and the key supplied with --key becomes its attestation
verification key. The token signature is checked against that key first, unless
--skip-verify is given.

	gen-corim psa token.cbor --key=iak-pub.json --template-dir=templates

--key may name an IAK certificate rather than a bare key. Given
--trust-anchors, the certificate is verified to those anchors before its key is
trusted, and --crl checks the chain against a revocation list. Without
--trust-anchors the certificate is only a container for the key, and nothing
vouches for it.

	gen-corim psa token.cbor --key=iak.pem --trust-anchors=ca.pem \
		--template-dir=templates
`
}

func (o *Scheme) Args() cobra.PositionalArgs { return cobra.ExactArgs(1) }

// Generate decodes the token, verifies it and turns its claims into a CoMID.
func (o *Scheme) Generate(
	fs afero.Fs, b scheme.ComidBuilder, args []string,
) ([]scheme.Payload, error) {
	if o.KeyFile() == "" && !o.SkipVerify() {
		return nil, errors.New("no key supplied: use --key, or --skip-verify to generate from an unverified token")
	}

	v, err := o.Resolve(fs)
	if err != nil {
		return nil, err
	}

	token, err := afero.ReadFile(fs, args[0])
	if err != nil {
		return nil, fmt.Errorf("error loading token from %s: %w", args[0], err)
	}

	evidence, err := psatoken.DecodeAndValidateEvidenceFromCOSE(token)
	if err != nil {
		return nil, fmt.Errorf("error decoding token from %s: %w", args[0], err)
	}

	var verifKey *comid.CryptoKey

	if v.Key != nil {
		if v.Mode == scheme.ModeChain {
			if err = v.VerifyLeaf(time.Now()); err != nil {
				return nil, fmt.Errorf("error verifying the certificate in %s: %w", o.KeyFile(), err)
			}
		}

		if v.Mode != scheme.ModeSkip {
			if err = evidence.Verify(v.Key); err != nil {
				return nil, fmt.Errorf("error verifying token from %s: %w", args[0], err)
			}
		}

		if verifKey, err = keyutil.PKIXBase64Key(v.Key); err != nil {
			return nil, err
		}
	}

	m, err := b.NewComid(corimpsa.ProfileURI)
	if err != nil {
		return nil, err
	}

	if err := addTriples(m, evidence.Claims, verifKey); err != nil {
		return nil, err
	}

	if err := m.Valid(); err != nil {
		return nil, fmt.Errorf("error validating the generated CoMID: %w", err)
	}

	return []scheme.Payload{{
		Profile: corimpsa.ProfileURI,
		Comids:  []*comid.Comid{m},
	}}, nil
}

// addTriples populates the CoMID with the reference values and the attestation
// verification key derived from the token claims.
func addTriples(m *comid.Comid, claims psatoken.IClaims, verifKey *comid.CryptoKey) error {
	implID, err := claims.GetImplID()
	if err != nil {
		return fmt.Errorf("error extracting implementation ID: %w", err)
	}

	class := corimpsa.NewClassImplID(implID)

	measurements, err := Measurements(claims)
	if err != nil {
		return err
	}

	// The Comid.Add* wrappers are used rather than their Triples
	// counterparts because only the former create the triple list when it is
	// still nil.
	if m.AddReferenceValue(&comid.ValueTriple{
		Environment:  comid.Environment{Class: class},
		Measurements: *measurements,
	}) == nil {
		return errors.New("error adding the reference value")
	}

	if verifKey == nil {
		return nil
	}

	instID, err := claims.GetInstID()
	if err != nil {
		return fmt.Errorf("error extracting instance ID: %w", err)
	}

	instance, err := comid.NewUEIDInstance(instID)
	if err != nil {
		return fmt.Errorf("error creating instance ID: %w", err)
	}

	keys := comid.NewCryptoKeys().Add(verifKey)

	if m.AddAttestVerifKey(&comid.KeyTriple{
		Environment: comid.Environment{Class: class, Instance: instance},
		VerifKeys:   *keys,
	}) == nil {
		return errors.New("error adding the attestation verification key")
	}

	return nil
}

// Measurements turns the software components of a PSA token into the
// measurements of a PSA reference value, as described by section 3.3 of the PSA
// endorsements specification: one measurement per software component, keyed by
// the "psa.software-component" string, carrying the component digest and its
// signer ID.
func Measurements(claims psatoken.IClaims) (*comid.Measurements, error) {
	components, err := claims.GetSoftwareComponents()
	if err != nil {
		return nil, fmt.Errorf("error extracting software components: %w", err)
	}

	measurements := comid.NewMeasurements()

	for i, component := range components {
		// a PSA token has no token-wide hash algorithm claim
		measurement, err := SwComponentMeasurement(
			component, corimpsa.PSASoftwareComponentMkey, "")
		if err != nil {
			return nil, fmt.Errorf("software component at index %d: %w", i, err)
		}

		measurements.Add(measurement)
	}

	if len(measurements.Values) == 0 {
		return nil, errors.New("the token carries no software components")
	}

	return measurements, nil
}

// SwComponentMeasurement converts a single software component into a
// measurement under the supplied measurement key. The CCA platform profile
// describes the same shape under a different key, so it shares this code.
//
// hashAlgID is the algorithm the token names for its measurements as a whole,
// and may be empty: PSA tokens have no such claim, and describe the algorithm
// per component instead.
func SwComponentMeasurement(
	component psatoken.ISwComponent, mkey, hashAlgID string,
) (*comid.Measurement, error) {
	measurement, err := comid.NewMeasurement(mkey, comid.StringType)
	if err != nil {
		return nil, err
	}

	value, err := component.GetMeasurementValue()
	if err != nil {
		return nil, fmt.Errorf("error extracting measurement value: %w", err)
	}

	// the measurement description names the hash algorithm of this component
	// and is more specific than the token-wide claim, but it is optional
	name := hashAlgID
	if desc, derr := component.GetMeasurementDesc(); derr == nil && desc != "" {
		name = desc
	}

	algID, err := scheme.DigestAlgorithm(value, name)
	if err != nil {
		return nil, err
	}

	if measurement.AddDigest(algID, value) == nil {
		return nil, fmt.Errorf("error adding the measurement value")
	}

	signerID, err := component.GetSignerID()
	if err != nil {
		return nil, fmt.Errorf("error extracting signer ID: %w", err)
	}

	signerKey, err := comid.NewCryptoKeyTaggedBytes(signerID)
	if err != nil {
		return nil, fmt.Errorf("error creating signer ID: %w", err)
	}

	measurement.AddCryptoKey(signerKey)

	// measurement type and version are optional in a PSA token
	if measurementType, err := component.GetMeasurementType(); err == nil {
		measurement.SetName(measurementType)
	}

	if version, err := component.GetVersion(); err == nil {
		measurement.Val.Ver = comid.NewVersion().SetVersion(version)
	}

	return measurement, nil
}
