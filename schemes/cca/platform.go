// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"errors"
	"fmt"

	"github.com/veraison/ccatoken"
	ccaplatform "github.com/veraison/ccatoken/platform"
	"github.com/veraison/corim/comid"
	corimcca "github.com/veraison/corim/profiles/cca"
	"github.com/veraison/gen-corim/scheme"
	genpsa "github.com/veraison/gen-corim/schemes/psa"
)

//nolint:dupl // the same shape as realmPayload, over a different profile and claims
func platformPayload(b scheme.ComidBuilder, evidence *ccatoken.Evidence) (*scheme.Payload, error) {
	// never nil: ccatoken.Evidence.Validate makes both claim sets mandatory
	claims := evidence.PlatformClaims

	m, err := b.NewComid(corimcca.PlatformProfileURI)
	if err != nil {
		return nil, err
	}

	if err := addPlatformTriples(m, claims); err != nil {
		return nil, err
	}

	if err := m.Valid(); err != nil {
		return nil, fmt.Errorf("error validating the generated platform CoMID: %w", err)
	}

	return &scheme.Payload{
		Profile: corimcca.PlatformProfileURI,
		Label:   PartPlatform,
		Comids:  []*comid.Comid{m},
	}, nil
}

func addPlatformTriples(m *comid.Comid, claims ccaplatform.IClaims) error {
	implID, err := claims.GetImplID()
	if err != nil {
		return fmt.Errorf("error extracting implementation ID: %w", err)
	}

	class, err := corimcca.NewClassPlatformImplID(implID)
	if err != nil {
		return fmt.Errorf("error creating implementation ID: %w", err)
	}

	measurements, err := platformMeasurements(claims)
	if err != nil {
		return err
	}

	if m.AddReferenceValue(&comid.ValueTriple{
		Environment:  comid.Environment{Class: class},
		Measurements: *measurements,
	}) == nil {
		return errors.New("error adding the reference value")
	}

	return nil
}

// platformMeasurements turns the platform claims into the measurements of a CCA
// platform reference value: one "cca.software-component" per software component
// - the same shape as PSA, under a different measurement key - followed by the
// "cca.platform-config" measurement carrying the platform configuration.
func platformMeasurements(claims ccaplatform.IClaims) (*comid.Measurements, error) {
	components, err := claims.GetSoftwareComponents()
	if err != nil {
		return nil, fmt.Errorf("error extracting software components: %w", err)
	}

	// the platform token names the algorithm its measurements were taken
	// with; individual components may name their own
	hashAlgID, _ := claims.GetHashAlgID()

	measurements := comid.NewMeasurements()

	for i, component := range components {
		measurement, merr := genpsa.SwComponentMeasurement(
			component, corimcca.CCASoftwareComponentMkey, hashAlgID)
		if merr != nil {
			return nil, fmt.Errorf("software component at index %d: %w", i, merr)
		}

		// The component version has to be dropped. The profile says it is
		// optional and that a version-scheme must not accompany it, but
		// corim's validator reads Ver.Scheme.String() through a nil
		// pointer when the scheme is absent (profiles/cca/platform.go,
		// validateCCASoftwareComponent) and rejects the measurement when
		// it is present - so a version can be carried in neither form.
		// Restore this once the nil dereference is fixed upstream.
		measurement.Val.Ver = nil

		measurements.Add(measurement)
	}

	if len(measurements.Values) == 0 {
		return nil, errors.New("the token carries no software components")
	}

	config, err := claims.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("error extracting the platform configuration: %w", err)
	}

	configMeasurement, err := platformConfigMeasurement(config)
	if err != nil {
		return nil, err
	}

	measurements.Add(configMeasurement)

	return measurements, nil
}

// platformConfigMeasurement wraps the platform configuration in a
// "cca.platform-config" measurement.
//
// The profile makes raw-value-mask mandatory alongside raw-value, and
// SetRawValueBytes drops a zero-length mask, so an all-ones mask of the value's
// length is supplied: every bit of the configuration is significant.
func platformConfigMeasurement(config []byte) (*comid.Measurement, error) {
	if len(config) == 0 {
		return nil, errors.New("the token carries an empty platform configuration")
	}

	measurement, err := comid.NewMeasurement(
		corimcca.CCAPlatformConfigMkey, comid.StringType)
	if err != nil {
		return nil, err
	}

	mask := make([]byte, len(config))
	for i := range mask {
		mask[i] = 0xff
	}

	if measurement.SetRawValueBytes(config, mask) == nil {
		return nil, errors.New("error adding the platform configuration")
	}

	return measurement, nil
}
