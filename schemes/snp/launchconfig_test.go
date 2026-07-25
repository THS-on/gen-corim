// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeLaunchConfig writes a launch configuration to a temporary file and
// returns its path.
func writeLaunchConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "launch-config.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0600))

	return path
}

func loadLaunchConfig(t *testing.T, contents string) (*LaunchConfig, error) {
	t.Helper()

	return LoadLaunchConfig(afero.NewOsFs(), writeLaunchConfig(t, contents))
}

// A configuration written for an earlier version keeps its meaning: it gets the
// values that used to be hard coded.
func Test_LoadLaunchConfig_defaults(t *testing.T) {
	config, err := loadLaunchConfig(t, `{"max-vcpus": 4, "cpu-model": "EPYC-Milan-v2"}`)
	require.NoError(t, err)

	assert.Equal(t, DefaultGuestFeatures, config.GuestFeatures)
	assert.Equal(t, GuestFeatures(0x1), config.GuestFeatures)
	assert.Equal(t, QEMU, config.VMMType)
}

func Test_LoadLaunchConfig_guest_features(t *testing.T) {
	for _, tv := range []struct {
		name     string
		value    string
		expected GuestFeatures
	}{
		{name: "hex", value: `"0x21"`, expected: 0x21},
		{name: "upper case", value: `"0XAB"`, expected: 0xab},
		{name: "all 64 bits", value: `"0xffffffffffffffff"`, expected: 0xffffffffffffffff},
	} {
		t.Run(tv.name, func(t *testing.T) {
			config, err := loadLaunchConfig(t,
				`{"max-vcpus": 1, "cpu-model": "EPYC-v4", "guest-features": `+tv.value+`}`)
			require.NoError(t, err)

			assert.Equal(t, tv.expected, config.GuestFeatures)
		})
	}
}

// A field that is misspelled, missing, out of range or of the wrong shape is
// reported rather than ignored.
func Test_LoadLaunchConfig_schema_violations(t *testing.T) {
	for _, tv := range []struct {
		name     string
		contents string
		expected string
	}{
		{
			name:     "misspelled field",
			contents: `{"maxvcpus": 4, "cpu-model": "EPYC-v4"}`,
			expected: "additional properties 'maxvcpus' not allowed",
		},
		{
			name:     "missing cpu-model",
			contents: `{"max-vcpus": 4}`,
			expected: "missing property 'cpu-model'",
		},
		{
			name:     "missing max-vcpus",
			contents: `{"cpu-model": "EPYC-v4"}`,
			expected: "missing property 'max-vcpus'",
		},
		{
			name:     "zero max-vcpus",
			contents: `{"max-vcpus": 0, "cpu-model": "EPYC-v4"}`,
			expected: "minimum: got 0, want 1",
		},
		{
			name:     "fractional max-vcpus",
			contents: `{"max-vcpus": 1.5, "cpu-model": "EPYC-v4"}`,
			expected: "got number, want integer",
		},
		{
			name:     "empty cpu-model",
			contents: `{"max-vcpus": 4, "cpu-model": ""}`,
			expected: "minLength: got 0, want 1",
		},
		{
			name:     "guest features as a number",
			contents: `{"max-vcpus": 4, "cpu-model": "EPYC-v4", "guest-features": 33}`,
			expected: "got number, want string",
		},
		{
			name:     "guest features in decimal",
			contents: `{"max-vcpus": 4, "cpu-model": "EPYC-v4", "guest-features": "33"}`,
			expected: "does not match pattern",
		},
		{
			name:     "guest features not hex",
			contents: `{"max-vcpus": 4, "cpu-model": "EPYC-v4", "guest-features": "0x2g"}`,
			expected: "does not match pattern",
		},
		{
			name:     "guest features wider than 64 bits",
			contents: `{"max-vcpus": 4, "cpu-model": "EPYC-v4", "guest-features": "0x10000000000000000"}`,
			expected: "does not match pattern",
		},
		{
			name:     "unknown vmm type",
			contents: `{"max-vcpus": 4, "cpu-model": "EPYC-v4", "vmm-type": "cloud-hypervisor"}`,
			expected: "value must be one of 'qemu', 'ec2'",
		},
		{
			name:     "not an object",
			contents: `[]`,
			expected: "got array, want object",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			_, err := loadLaunchConfig(t, tv.contents)

			require.ErrorContains(t, err, "error validating launch configuration from")
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

// A configuration file has been through the schema by the time it is decoded,
// so these are the errors that only a caller decoding JSON itself can reach.
func Test_GuestFeatures_UnmarshalJSON_rejects(t *testing.T) {
	for _, tv := range []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "a number",
			value:    `33`,
			expected: `guest-features must be a string holding a hex bitmask, such as "0x21"`,
		},
		{
			name:     "decimal",
			value:    `"33"`,
			expected: `guest-features "33" is not a hex bitmask: it needs a "0x" prefix`,
		},
		{
			name:     "not hex",
			value:    `"0x2g"`,
			expected: `guest-features "0x2g" is not a 64-bit hex bitmask`,
		},
		{
			name:     "wider than 64 bits",
			value:    `"0x10000000000000000"`,
			expected: `guest-features "0x10000000000000000" is not a 64-bit hex bitmask`,
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			var features GuestFeatures

			err := json.Unmarshal([]byte(tv.value), &features)
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

// A file may point at the schema, so that an editor validates it too.
func Test_LoadLaunchConfig_schema_reference_is_allowed(t *testing.T) {
	config, err := loadLaunchConfig(t, `{
		"$schema": "https://veraison.github.io/gen-corim/schemes/snp/launch-config.schema.json",
		"max-vcpus": 2,
		"cpu-model": "EPYC-v4"
	}`)
	require.NoError(t, err)

	assert.Equal(t, 2, config.MaxVCPUs)
}

func Test_LaunchConfig_marshals_back(t *testing.T) {
	config := LaunchConfig{
		MaxVCPUs:      4,
		CPUModel:      "EPYC-v4",
		GuestFeatures: 0x21,
		VMMType:       EC2,
	}

	data, err := json.Marshal(&config)
	require.NoError(t, err)

	assert.JSONEq(t,
		`{"max-vcpus": 4, "cpu-model": "EPYC-v4", "guest-features": "0x21", "vmm-type": "ec2"}`,
		string(data))

	// what it marshals to is what it loads back from
	loaded, err := loadLaunchConfig(t, string(data))
	require.NoError(t, err)

	assert.Equal(t, config, *loaded)
}

func Test_VMMType_json(t *testing.T) {
	var vmmType VMMType

	require.NoError(t, json.Unmarshal([]byte(`"ec2"`), &vmmType))
	assert.Equal(t, EC2, vmmType)

	err := json.Unmarshal([]byte(`"cloud-hypervisor"`), &vmmType)
	assert.ErrorContains(t, err, `unknown vmm-type "cloud-hypervisor", want one of ec2, qemu`)

	err = json.Unmarshal([]byte(`2`), &vmmType)
	assert.ErrorContains(t, err, "vmm-type must be a string, one of ec2, qemu")

	// a type from neither the schema nor the constants has no name to write,
	// and is not silently given one
	_, err = json.Marshal(VMMType(7))
	assert.ErrorContains(t, err, "unknown vmm-type VMMType(7)")
}
