// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package psa generates PSA endorsements from a PSA attestation token.
package psa

import (
	"errors"
	"fmt"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/veraison/corim/comid"
	corimpsa "github.com/veraison/corim/profiles/psa"
	"github.com/veraison/gen-corim/scheme"
	"github.com/veraison/psatoken"
)

// Scheme generates a CoRIM carrying the reference values of a PSA attester.
type Scheme struct{}

// New returns a PSA scheme with its own flag state.
func New() scheme.Scheme { return &Scheme{} }

func (o *Scheme) Use() string { return "psa <token-file>" }

func (o *Scheme) Short() string { return "generate PSA endorsements from a PSA token" }

func (o *Scheme) Long() string {
	return `Generate PSA endorsements from a PSA attestation token.

The software components of the token become the reference values of the
generated CoRIM.

	gen-corim psa token.cbor --template-dir=templates
`
}

func (o *Scheme) Args() cobra.PositionalArgs { return cobra.ExactArgs(1) }

func (o *Scheme) AddFlags(flags *pflag.FlagSet) {}

// Generate decodes the token and turns its claims into a CoMID.
func (o *Scheme) Generate(
	fs afero.Fs, b scheme.ComidBuilder, args []string,
) ([]scheme.Payload, error) {
	token, err := afero.ReadFile(fs, args[0])
	if err != nil {
		return nil, fmt.Errorf("error loading token from %s: %w", args[0], err)
	}

	evidence, err := psatoken.DecodeAndValidateEvidenceFromCOSE(token)
	if err != nil {
		return nil, fmt.Errorf("error decoding token from %s: %w", args[0], err)
	}

	m, err := b.NewComid(corimpsa.ProfileURI)
	if err != nil {
		return nil, err
	}

	if err := addTriples(m, evidence.Claims); err != nil {
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

// addTriples populates the CoMID with the reference values derived from the
// token claims.
func addTriples(m *comid.Comid, claims psatoken.IClaims) error {
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
