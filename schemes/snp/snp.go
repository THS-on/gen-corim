// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package snp generates AMD SEV-SNP reference values from an attestation
// report.
package snp

import (
	"errors"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
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
	ovmfFile       string
	launchConfFile string
	cspID          string
}

// New returns a SEV-SNP scheme with its own flag state.
func New() scheme.Scheme { return &Scheme{} }

func (o *Scheme) Use() string { return "snp <report-file>" }

func (o *Scheme) Short() string {
	return "generate SEV-SNP reference values from an attestation report"
}

func (o *Scheme) Long() string {
	return `Generate AMD SEV-SNP reference values from an attestation report.

There are two ways to describe the launch measurement of the confidential VMs
the reference values apply to.

Given --ovmf and --launch-config, the launch measurement is computed from the
firmware image, once for every vCPU count from 1 up to the max-vcpus of the
launch configuration, and one CoMID is generated per count. This describes VMs
that have not been launched yet.

	gen-corim snp report.bin --launch-config=launch.json \
		--ovmf=OVMF_CODE.fd --template-dir=templates

Given neither, the launch measurement is taken from the report as it stands and
a single CoMID is generated. The report's own measurement already binds the
vCPU count, CPU model and firmware of the machine that produced it, so no
launch configuration is accepted in this mode.

	gen-corim snp report.bin --template-dir=templates
`
}

func (o *Scheme) Args() cobra.PositionalArgs { return cobra.ExactArgs(1) }

func (o *Scheme) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.ovmfFile, "ovmf", "",
		"OVMF firmware image the VM boots, used to compute its launch measurement")
	flags.StringVarP(&o.launchConfFile, "launch-config", "l", "",
		"JSON file describing the VM the launch measurement is computed for")
	flags.StringVar(&o.cspID, "csp-id", "",
		"identifier of the cloud service provider, for reports signed by a CSP")
}

// Generate reads the report and turns it into one CoMID per vCPU count.
func (o *Scheme) Generate(
	fs afero.Fs, b scheme.ComidBuilder, args []string,
) ([]scheme.Payload, error) {
	if err := o.validFlags(); err != nil {
		return nil, err
	}

	raw, err := afero.ReadFile(fs, args[0])
	if err != nil {
		return nil, fmt.Errorf("error loading report from %s: %w", args[0], err)
	}

	report, err := abi.ReportToProto(raw)
	if err != nil {
		return nil, fmt.Errorf("error decoding report from %s: %w", args[0], err)
	}

	launchMeasurements, err := o.launchMeasurements(fs, report)
	if err != nil {
		return nil, err
	}

	env, err := environment(report, o.cspID)
	if err != nil {
		return nil, err
	}

	comids := make([]*comid.Comid, 0, len(launchMeasurements))

	for _, launchMeasurement := range launchMeasurements {
		m, err := b.NewComid(ProfileURI)
		if err != nil {
			return nil, err
		}

		if m.AddReferenceValue(&comid.ValueTriple{
			Environment:  *env,
			Measurements: *measurements(report, launchMeasurement),
		}) == nil {
			return nil, errors.New("error adding the reference value")
		}

		if err := m.Valid(); err != nil {
			return nil, fmt.Errorf("error validating the generated CoMID: %w", err)
		}

		comids = append(comids, m)
	}

	return []scheme.Payload{{Profile: ProfileURI, Comids: comids}}, nil
}

func (o *Scheme) validFlags() error {
	// The two ways of arriving at a launch measurement are exclusive:
	// computing one needs both the firmware and the VM shape, and taking the
	// report's own needs neither.
	if (o.ovmfFile == "") != (o.launchConfFile == "") {
		return errors.New(
			"--ovmf and --launch-config must be used together: supply both to compute launch " +
				"measurements, or neither to use the one in the report")
	}

	return nil
}

// launchMeasurements returns the value of MKey 641 for each CoMID to generate.
func (o *Scheme) launchMeasurements(fs afero.Fs, report *sevsnp.Report) ([][]byte, error) {
	if o.ovmfFile == "" {
		return [][]byte{report.GetMeasurement()}, nil
	}

	config, err := LoadLaunchConfig(fs, o.launchConfFile)
	if err != nil {
		return nil, err
	}

	return launchDigests(config, o.ovmfFile)
}
