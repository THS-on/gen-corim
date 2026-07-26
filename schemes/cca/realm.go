// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cca

import (
	"errors"
	"fmt"

	"github.com/veraison/ccatoken"
	ccarealm "github.com/veraison/ccatoken/realm"
	"github.com/veraison/corim/comid"
	corimcca "github.com/veraison/corim/profiles/cca"
	"github.com/veraison/gen-corim/scheme"
)

// realmExtendedMeasurementMkeys are the measurement keys of the realm extended
// measurements, in register order.
var realmExtendedMeasurementMkeys = []string{
	corimcca.CCARealmExtendedMeasurement0Mkey,
	corimcca.CCARealmExtendedMeasurement1Mkey,
	corimcca.CCARealmExtendedMeasurement2Mkey,
	corimcca.CCARealmExtendedMeasurement3Mkey,
}

func realmPayload(
	b scheme.ComidBuilder, evidence *ccatoken.Evidence,
) (*scheme.Payload, error) {
	// never nil: ccatoken.Evidence.Validate makes both claim sets mandatory
	claims := evidence.RealmClaims

	m, err := b.NewComid(corimcca.RealmProfileURI)
	if err != nil {
		return nil, err
	}

	if err := addRealmTriples(m, claims); err != nil {
		return nil, err
	}

	if err := m.Valid(); err != nil {
		return nil, fmt.Errorf("error validating the generated realm CoMID: %w", err)
	}

	return &scheme.Payload{
		Profile: corimcca.RealmProfileURI,
		Label:   PartRealm,
		Comids:  []*comid.Comid{m},
	}, nil
}

// addRealmTriples populates the CoMID with the realm reference value. A realm
// carries no attestation verification key: it is identified by its initial
// measurement rather than by a key.
func addRealmTriples(m *comid.Comid, claims ccarealm.IClaims) error {
	rim, err := claims.GetInitialMeasurement()
	if err != nil {
		return fmt.Errorf("error extracting the realm initial measurement: %w", err)
	}

	// The realm initial measurement identifies the target environment, and
	// is also carried as a measurement in its own right.
	class, err := corimcca.NewClassRealmRIM(rim)
	if err != nil {
		return fmt.Errorf("error creating the realm initial measurement: %w", err)
	}

	measurements, err := realmMeasurements(claims, rim)
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

// realmMeasurements turns the realm claims into the measurements of a realm
// reference value: the mandatory initial measurement, the extended measurements
// of the realm extensible registers, and the personalization value when the
// realm was given one.
func realmMeasurements(claims ccarealm.IClaims, rim []byte) (*comid.Measurements, error) {
	// the hash algorithm is a mandatory realm claim, but ccatoken only checks
	// that it is a non-empty string, so it may disagree with the
	// measurements it describes
	hashAlgID, _ := claims.GetHashAlgID()

	measurements := comid.NewMeasurements()

	initial, err := digestMeasurement(corimcca.CCARealmInitialMeasurementMkey, hashAlgID, rim)
	if err != nil {
		return nil, err
	}

	measurements.Add(initial)

	extended, err := claims.GetExtensibleMeasurements()
	if err != nil {
		return nil, fmt.Errorf("error extracting the realm extended measurements: %w", err)
	}

	if len(extended) > len(realmExtendedMeasurementMkeys) {
		return nil, fmt.Errorf("the token carries %d realm extended measurements, at most %d are defined",
			len(extended), len(realmExtendedMeasurementMkeys))
	}

	for i, rem := range extended {
		measurement, merr := digestMeasurement(realmExtendedMeasurementMkeys[i], hashAlgID, rem)
		if merr != nil {
			return nil, fmt.Errorf("realm extended measurement %d: %w", i, merr)
		}

		measurements.Add(measurement)
	}

	// the personalization value is optional
	if rpv, err := claims.GetPersonalizationValue(); err == nil && len(rpv) > 0 {
		measurement, err := comid.NewMeasurement(
			corimcca.CCARealmPersonalizationMkey, comid.StringType)
		if err != nil {
			return nil, err
		}

		if measurement.SetRawValueBytes(rpv, nil) == nil {
			return nil, errors.New("error adding the realm personalization value")
		}

		measurements.Add(measurement)
	}

	return measurements, nil
}

func digestMeasurement(mkey, hashAlgID string, value []byte) (*comid.Measurement, error) {
	measurement, err := comid.NewMeasurement(mkey, comid.StringType)
	if err != nil {
		return nil, err
	}

	algID, err := scheme.DigestAlgorithm(value, hashAlgID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mkey, err)
	}

	if measurement.AddDigest(algID, value) == nil {
		return nil, fmt.Errorf("error adding the %s digest", mkey)
	}

	return measurement, nil
}
