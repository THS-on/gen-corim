// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

// guestFeatures is the SNP guest feature set assumed when computing a launch
// measurement.
const guestFeatures = 0x1

// LaunchConfig describes the shape of the confidential VM whose launch
// measurements are to be computed. It cannot be derived from the report,
// because the point of the exercise is to describe machines that have not run
// yet.
type LaunchConfig struct {
	// MaxVCPUs is the largest vCPU count to generate reference values for.
	// A launch measurement depends on the vCPU count, so one is computed
	// for every count from 1 up to this value.
	MaxVCPUs int `json:"max-vcpus"`
	// CPUModel is the QEMU CPU model of the VM, for instance
	// "EPYC-Milan-v2".
	CPUModel string `json:"cpu-model"`
}

// Valid returns an error if the launch configuration is unusable.
func (o *LaunchConfig) Valid() error {
	if o.MaxVCPUs < 1 {
		return fmt.Errorf("max-vcpus must be at least 1, got %d", o.MaxVCPUs)
	}

	if o.CPUModel == "" {
		return fmt.Errorf("cpu-model not specified")
	}

	return nil
}

// LoadLaunchConfig reads a launch configuration from the named JSON file.
func LoadLaunchConfig(fs afero.Fs, path string) (*LaunchConfig, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("error loading launch configuration from %s: %w", path, err)
	}

	var config LaunchConfig

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error decoding launch configuration from %s: %w", path, err)
	}

	if err := config.Valid(); err != nil {
		return nil, fmt.Errorf("error validating launch configuration from %s: %w", path, err)
	}

	return &config, nil
}

// directBoot describes a kernel the VM is booted with directly, rather than
// through the firmware's own boot path. All three parts are optional, but they
// change the launch measurement when present.
type directBoot struct {
	kernel  []byte
	initrd  []byte
	cmdline string
}

// launchDigests computes the launch measurement of the described VM for every
// vCPU count from 1 to MaxVCPUs.
//
// The OVMF image is read by sev-snp-measure-go itself rather than through the
// supplied filesystem, so it has to exist on the real one.
func launchDigests(config *LaunchConfig, ovmfFile string, boot *directBoot) ([][]byte, error) {
	ovmfObj, err := ovmf.New(ovmfFile)
	if err != nil {
		return nil, fmt.Errorf("error loading OVMF from %s: %w", ovmfFile, err)
	}

	ovmfHash, err := guest.OVMFHash(ovmfObj)
	if err != nil {
		return nil, fmt.Errorf("error hashing OVMF from %s: %w", ovmfFile, err)
	}

	digests := make([][]byte, 0, config.MaxVCPUs)

	for vcpus := 1; vcpus <= config.MaxVCPUs; vcpus++ {
		digest, err := guest.LaunchDigestFromOVMF(
			ovmfObj, guestFeatures, vcpus, ovmfHash, vmmtypes.QEMU, config.CPUModel,
			boot.kernel, boot.initrd, boot.cmdline)
		if err != nil {
			return nil, fmt.Errorf("error computing the launch digest for %d vCPUs: %w", vcpus, err)
		}

		digests = append(digests, digest)
	}

	return digests, nil
}
