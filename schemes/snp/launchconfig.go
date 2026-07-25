// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/spf13/afero"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/ovmf"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

// launchConfigSchema is the format every launch configuration file is checked
// against. It is a file of its own so that editors and other validators can use
// it too.
//
//go:embed launch-config.schema.json
var launchConfigSchema []byte

// launchConfigSchemaURI is the $id of the embedded schema; nothing is fetched
// from it.
const launchConfigSchemaURI = "https://veraison.github.io/gen-corim/schemes/snp/launch-config.schema.json"

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(launchConfigSchema))
	if err != nil {
		return nil, fmt.Errorf("error decoding the embedded launch configuration schema: %w", err)
	}

	c := jsonschema.NewCompiler()

	if err = c.AddResource(launchConfigSchemaURI, doc); err != nil {
		return nil, fmt.Errorf("error loading the embedded launch configuration schema: %w", err)
	}

	schema, err := c.Compile(launchConfigSchemaURI)
	if err != nil {
		return nil, fmt.Errorf("error compiling the embedded launch configuration schema: %w", err)
	}

	return schema, nil
})

// GuestFeatures is the SEV_FEATURES bitfield of the initial VMSA: bit 0 is
// SNPActive, bit 5 DebugSwap.
type GuestFeatures uint64

// DefaultGuestFeatures is SNPActive alone, which is what a VMM launches an SNP
// guest with unless it is told otherwise.
const DefaultGuestFeatures GuestFeatures = 0x1

// UnmarshalJSON reads a hex bitmask in a string, the spelling AMD's
// documentation and sev-snp-measure use.
func (o *GuestFeatures) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf(`guest-features must be a string holding a hex bitmask, such as "0x21": %w`, err)
	}

	digits, found := strings.CutPrefix(strings.ToLower(s), "0x")
	if !found {
		return fmt.Errorf(`guest-features %q is not a hex bitmask: it needs a "0x" prefix`, s)
	}

	features, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return fmt.Errorf("guest-features %q is not a 64-bit hex bitmask", s)
	}

	*o = GuestFeatures(features)

	return nil
}

func (o GuestFeatures) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o GuestFeatures) String() string {
	return "0x" + strconv.FormatUint(uint64(o), 16)
}

// VMMType is the virtual machine monitor that starts the VM. It decides part of
// the initial vCPU state and when the CPUID page is measured, and so takes part
// in the launch measurement.
type VMMType vmmtypes.VMMType

const (
	QEMU = VMMType(vmmtypes.QEMU)
	// EC2 is the AWS Nitro hypervisor.
	EC2 = VMMType(vmmtypes.EC2)
)

// vmmTypes are the names the schema allows, and what they mean.
var vmmTypes = map[string]VMMType{
	"qemu": QEMU,
	"ec2":  EC2,
}

func (o *VMMType) UnmarshalJSON(data []byte) error {
	var s string

	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("vmm-type must be a string, one of %s: %w", knownVMMTypes(), err)
	}

	vmmType, ok := vmmTypes[s]
	if !ok {
		return fmt.Errorf("unknown vmm-type %q, want one of %s", s, knownVMMTypes())
	}

	*o = vmmType

	return nil
}

func (o VMMType) MarshalJSON() ([]byte, error) {
	if !o.valid() {
		return nil, fmt.Errorf("unknown vmm-type %s", o)
	}

	return json.Marshal(o.String())
}

func (o VMMType) String() string {
	switch o {
	case QEMU:
		return "qemu"
	case EC2:
		return "ec2"
	default:
		return fmt.Sprintf("VMMType(%d)", int(o))
	}
}

func (o VMMType) valid() bool {
	return o == QEMU || o == EC2
}

func knownVMMTypes() string {
	names := slices.Sorted(maps.Keys(vmmTypes))

	return strings.Join(names, ", ")
}

// LaunchConfig describes the shape of the confidential VM whose launch
// measurements are to be computed. It cannot be derived from the report,
// because the point of the exercise is to describe machines that have not run
// yet. launch-config.schema.json describes the same fields for the file it is
// loaded from.
type LaunchConfig struct {
	// MaxVCPUs is the largest vCPU count to generate reference values for.
	// A launch measurement depends on the vCPU count, so one is computed
	// for every count from 1 up to this value.
	MaxVCPUs int `json:"max-vcpus"`
	// CPUModel is the QEMU CPU model of the VM, for instance
	// "EPYC-Milan-v2".
	CPUModel string `json:"cpu-model"`
	// GuestFeatures defaults to DefaultGuestFeatures when a file leaves it
	// out.
	GuestFeatures GuestFeatures `json:"guest-features"`
	// VMMType defaults to QEMU when a file leaves it out.
	VMMType VMMType `json:"vmm-type"`
}

// Valid returns an error if the launch configuration is unusable.
func (o *LaunchConfig) Valid() error {
	if o.MaxVCPUs < 1 {
		return fmt.Errorf("max-vcpus must be at least 1, got %d", o.MaxVCPUs)
	}

	if o.CPUModel == "" {
		return fmt.Errorf("cpu-model not specified")
	}

	if !o.VMMType.valid() {
		return fmt.Errorf("unknown vmm-type %s, want one of %s", o.VMMType, knownVMMTypes())
	}

	return nil
}

// LoadLaunchConfig reads a launch configuration from the named JSON file,
// checking it against the schema first so that a misspelled or out-of-range
// field is an error rather than a silently ignored one.
func LoadLaunchConfig(fs afero.Fs, path string) (*LaunchConfig, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("error loading launch configuration from %s: %w", path, err)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error decoding launch configuration from %s: %w", path, err)
	}

	schema, err := compiledSchema()
	if err != nil {
		return nil, err
	}

	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("error validating launch configuration from %s: %w", path, err)
	}

	// an absent field leaves the default the schema documents in place
	config := LaunchConfig{GuestFeatures: DefaultGuestFeatures, VMMType: QEMU}

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
			ovmfObj, uint64(config.GuestFeatures), vcpus, ovmfHash,
			vmmtypes.VMMType(config.VMMType), config.CPUModel,
			boot.kernel, boot.initrd, boot.cmdline)
		if err != nil {
			return nil, fmt.Errorf("error computing the launch digest for %d vCPUs: %w", vcpus, err)
		}

		digests = append(digests, digest)
	}

	return digests, nil
}
