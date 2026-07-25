// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package snp generates AMD SEV-SNP reference values from an attestation
// report.
package snp

import (
	"errors"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/veraison/corim/comid"
	"github.com/veraison/gen-corim/scheme"
)

// ProfileURI is the AMD SEV-SNP CoRIM profile. The tag is the editor's copy's;
// the last published revision, draft-02, still says 2024:
//
//	https://github.com/deeglaze/draft-deeglaze-amd-sev-snp-corim-profile
const ProfileURI = "tag:amd.com,2025:snp-corim-profile"

// Scheme generates reference values from a SEV-SNP attestation report.
type Scheme struct {
	cspID string
}

// New returns a SEV-SNP scheme with its own flag state.
func New() scheme.Scheme { return &Scheme{} }

func (o *Scheme) Use() string { return "snp <report-file>" }

func (o *Scheme) Short() string {
	return "generate SEV-SNP reference values from an attestation report"
}

func (o *Scheme) Long() string {
	return `Generate AMD SEV-SNP reference values from an attestation report.

The launch measurement is taken from the report as it stands, so the reference
values describe the machine that produced it: its own measurement already binds
the vCPU count, CPU model and firmware of that machine.

	gen-corim snp report.bin --template-dir=templates
`
}

func (o *Scheme) Args() cobra.PositionalArgs { return cobra.ExactArgs(1) }

func (o *Scheme) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.cspID, "csp-id", "",
		"identifier of the cloud service provider, for reports signed by a CSP")
}

// Generate reads the report and turns it into a CoMID.
func (o *Scheme) Generate(
	fs afero.Fs, b scheme.ComidBuilder, args []string,
) ([]scheme.Payload, error) {
	raw, err := afero.ReadFile(fs, args[0])
	if err != nil {
		return nil, fmt.Errorf("error loading report from %s: %w", args[0], err)
	}

	report, err := abi.ReportToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("error decoding report from %s: %w", args[0], err)
	}

	env, err := environment(report, o.cspID)
	if err != nil {
		return nil, err
	}

	m, err := b.NewComid(ProfileURI)
	if err != nil {
		return nil, err
	}

	if m.AddReferenceValue(&comid.ValueTriple{
		Environment:  *env,
		Measurements: *measurements(report, report.GetMeasurement()),
	}) == nil {
		return nil, errors.New("error adding the reference value")
	}

	if err := m.Valid(); err != nil {
		return nil, fmt.Errorf("error validating the generated CoMID: %w", err)
	}

	return []scheme.Payload{{Profile: ProfileURI, Comids: []*comid.Comid{m}}}, nil
}
