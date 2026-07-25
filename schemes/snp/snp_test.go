// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"encoding/hex"
	"flag"
	"path/filepath"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/spf13/afero"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/gen-corim/generator"
	"github.com/veraison/gen-corim/scheme"
)

// update regenerates the golden CoRIMs instead of comparing against them.
var update = flag.Bool("update", false, "regenerate the golden CoRIMs")

const (
	testReport       = "../../data/snp/report.bin"
	testOVMF         = "../../data/snp/OVMF_CODE.cc.fd"
	testLaunchConfig = "../../data/snp/launch-config.json"
	testTemplate     = "../../data/templates/snp"

	// Unlike testOVMF, this firmware carries an SNP_KERNEL_HASHES metadata
	// section and so can measure a directly booted kernel. Its launch
	// config matches the inputs of the reference digest below.
	testDirectBootOVMF   = "../../data/snp/ovmf-amdsev-suffix.bin"
	testDirectBootConfig = "../../data/snp/launch-config-amdsev.json"
	testEmptyKernel      = "../../data/snp/empty-kernel.img"

	// referenceLaunchDigest is the launch measurement sev-snp-measure.py
	// produces for testDirectBootOVMF booting an empty kernel and initrd
	// with "console=ttyS0 loglevel=7" on one EPYC-v4 vCPU under QEMU. See
	// data/PROVENANCE.md.
	referenceLaunchDigest = "6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362" +
		"f390ef83a92046c042e706363b4b08fa"

	// The same firmware measured with guest features 0x21 rather than the
	// default 0x1: the snp_features_0x21_with_cmdline and
	// snp_4_vcpus_features_0x21 cases of guest/guest_test.go in
	// THS-on/sev-snp-measure-go (5963a48).
	referenceDigestFeatures0x21 = "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb28c653360fe4b3aba" +
		"7e534442e7e1e17895dfe778d0228977"
	referenceDigestFeatures0x21FourVCPUs = "4953b1fb416fa874980e8442b3706d345926d5f38879134e00813c5d7abcbe78" +
		"eafe7b422907be0b4698e2414a631942"

	goldenDir = "../../data/golden"

	// the vCPU count in launch-config.json, and so the number of CoMIDs a
	// synthesized run produces
	testMaxVCPUs = 4
)

// newFlagSet returns the scheme's flags, bound to that scheme instance.
func newFlagSet(t *testing.T, s scheme.Scheme) *pflag.FlagSet {
	t.Helper()

	flags := pflag.NewFlagSet("snp", pflag.ContinueOnError)
	s.AddFlags(flags)

	return flags
}

// generate runs the scheme over the supplied arguments. The first argument is
// the report; the rest are flags.
func generate(t *testing.T, args ...string) ([]scheme.Payload, error) {
	t.Helper()

	fs := afero.NewOsFs()

	s := New()

	flags := newFlagSet(t, s)
	require.NoError(t, flags.Parse(args[1:]))

	opts := &generator.Options{TemplateDir: testTemplate, Format: generator.FormatCBOR}

	g, err := generator.New(fs, opts, "snp")
	require.NoError(t, err)

	return s.Generate(fs, g, args[:1])
}

// launchMeasurementOf returns the MKey 641 digest of a CoMID.
func launchMeasurementOf(t *testing.T, m *comid.Comid) []byte {
	t.Helper()

	require.NotNil(t, m.Triples.ReferenceValues)
	require.Len(t, m.Triples.ReferenceValues.Values, 1)

	values := m.Triples.ReferenceValues.Values[0].Measurements.Values

	for i := range values {
		key, err := values[i].Key.GetKeyUint()
		require.NoError(t, err)

		if key == 641 {
			require.NotNil(t, values[i].Val.Digests)
			require.Len(t, *values[i].Val.Digests, 1)

			return (*values[i].Val.Digests)[0].Value
		}
	}

	t.Fatal("no launch measurement generated")

	return nil
}

// reportMeasurement returns the launch measurement the test report carries.
func reportMeasurement(t *testing.T) []byte {
	t.Helper()

	raw, err := afero.ReadFile(afero.NewOsFs(), testReport)
	require.NoError(t, err)

	report, err := abi.ReportToProto(raw)
	require.NoError(t, err)

	return report.GetMeasurement()
}

// In as-reported mode the launch measurement is the report's own, and exactly
// one CoMID is produced: the report already binds a single VM shape.
func Test_Generate_as_reported(t *testing.T) {
	payloads, err := generate(t, testReport)
	require.NoError(t, err)
	require.Len(t, payloads, 1)

	assert.Equal(t, "tag:amd.com,2025:snp-corim-profile", payloads[0].Profile)
	require.Len(t, payloads[0].Comids, 1)

	m := payloads[0].Comids[0]
	require.NoError(t, m.Valid())

	assert.Equal(t, reportMeasurement(t), launchMeasurementOf(t, m))
}

// In synthesized mode there is one CoMID per vCPU count, each with its own
// launch measurement, and none of them is the report's.
func Test_Generate_synthesized(t *testing.T) {
	payloads, err := generate(t, testReport,
		"--ovmf="+testOVMF, "--launch-config="+testLaunchConfig)
	require.NoError(t, err)
	require.Len(t, payloads, 1)
	require.Len(t, payloads[0].Comids, testMaxVCPUs)

	seen := make(map[string]bool, testMaxVCPUs)

	for _, m := range payloads[0].Comids {
		require.NoError(t, m.Valid())

		digest := launchMeasurementOf(t, m)
		assert.Len(t, digest, 48, "the launch measurement is a SHA-384 digest")

		// the launch measurement depends on the vCPU count, which is the
		// reason for generating one CoMID per count
		assert.False(t, seen[string(digest)], "duplicate launch measurement")
		seen[string(digest)] = true
	}
}

func Test_Generate_measurement_keys(t *testing.T) {
	payloads, err := generate(t, testReport)
	require.NoError(t, err)

	values := payloads[0].Comids[0].Triples.ReferenceValues.Values[0].Measurements.Values

	keys := make([]uint64, 0, len(values))

	for i := range values {
		key, err := values[i].Key.GetKeyUint()
		require.NoError(t, err)
		keys = append(keys, key)
	}

	// the mandatory keys of the AMD SEV-SNP profile; the optional ones are
	// only emitted when the corresponding report field is non-zero
	assert.Subset(t, keys, []uint64{0, 1, 2, 3, 4, 5, 6, 7, 641, 647, 3329, 3330, 3936, 3968})
}

// Which of the two class identifiers the environment carries, and what names it,
// is decided by the report's signer: a chip identifies itself by its chip ID, a
// CSP only by the identifier the caller supplies. The flags sharing signer_info
// with the signing key must not change which of the two a report is taken for.
func Test_environment(t *testing.T) {
	chipID := make([]byte, chipIDLen)
	for i := range chipID {
		chipID[i] = byte(i)
	}

	for _, tv := range []struct {
		name       string
		signerInfo uint32
		chipID     []byte
		cspID      string
		oid        string
		instance   []byte
		err        string
	}{
		{
			name:       "chip",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VcekReportSigner}),
			chipID:     chipID,
			oid:        "1.3.6.1.4.1.3704.3.1",
			instance:   chipID,
		},
		{
			// CHIP_ID masking zeroes the field, leaving nothing to
			// name the environment by
			name: "chip with a masked chip ID",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{
				SigningKey:  abi.VcekReportSigner,
				MaskChipKey: true,
			}),
			chipID: make([]byte, chipIDLen),
			oid:    "1.3.6.1.4.1.3704.3.1",
		},
		{
			name: "chip launched with an author key",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{
				SigningKey:  abi.VcekReportSigner,
				AuthorKeyEn: true,
			}),
			chipID:   chipID,
			oid:      "1.3.6.1.4.1.3704.3.1",
			instance: chipID,
		},
		{
			// the chip ID already names the environment, so the two
			// identifiers contradict each other
			name:       "chip with a CSP identifier",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VcekReportSigner}),
			chipID:     chipID,
			cspID:      "acme",
			err: "--csp-id does not apply to a report signed by a chip: it names the environment of a " +
				"report signed by a cloud service provider's VLEK",
		},
		{
			name:       "csp",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VlekReportSigner}),
			cspID:      "acme",
			oid:        "1.3.6.1.4.1.3704.3.2",
			instance:   []byte("acme"),
		},
		{
			// the report carries no name for the CSP, so without
			// --csp-id there is nothing to put in the instance
			name:       "csp without an identifier",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VlekReportSigner}),
			oid:        "1.3.6.1.4.1.3704.3.2",
		},
		{
			name: "csp launched with an author key and a masked chip ID",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{
				SigningKey:  abi.VlekReportSigner,
				AuthorKeyEn: true,
				MaskChipKey: true,
			}),
			cspID:    "acme",
			oid:      "1.3.6.1.4.1.3704.3.2",
			instance: []byte("acme"),
		},
		{
			name:       "unsigned report",
			signerInfo: abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.NoneReportSigner}),
			err:        "invalid signing key: None",
		},
		{
			// the reserved keys and the bits above the field are the
			// ABI's to reject, not this code's
			name:       "reserved signing key",
			signerInfo: 2 << 2,
			err:        "error parsing the signer info: signing_key values 2-6 are reserved. Got UNKNOWN(2)",
		},
		{
			name:       "reserved bits set",
			signerInfo: 1 << 5,
			err:        "error parsing the signer info: mbz range data[0x48:0x4C][0x5:0x1f] not all zero: 20",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			report := &sevsnp.Report{SignerInfo: tv.signerInfo, ChipId: tv.chipID}

			env, err := environment(report, tv.cspID)

			if tv.err != "" {
				assert.EqualError(t, err, tv.err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, env.Class)
			require.NotNil(t, env.Class.ClassID)

			oid, err := env.Class.ClassID.GetOID()
			require.NoError(t, err)
			assert.Equal(t, tv.oid, oid)

			if tv.instance == nil {
				assert.Nil(t, env.Instance)
				return
			}

			require.NotNil(t, env.Instance)
			assert.Equal(t, tv.instance, env.Instance.Bytes())
		})
	}
}

func Test_Generate_errors(t *testing.T) {
	for _, tv := range []struct {
		name     string
		report   string
		args     []string
		expected string
	}{
		{
			name:     "absent report",
			report:   "../../data/snp/absent.bin",
			expected: "error loading report from",
		},
		{
			// a launch config is not a report
			name:     "not a report",
			report:   testLaunchConfig,
			expected: "error decoding report from",
		},
		{
			// the two flags are meaningless apart: one says what to
			// measure, the other what to measure it for
			name:   "ovmf without a launch config",
			report: testReport,
			args:   []string{"--ovmf=" + testOVMF},
			expected: "--ovmf and --launch-config must be used together: supply both to " +
				"compute launch measurements, or neither to use the one in the report",
		},
		{
			name:     "launch config without ovmf",
			report:   testReport,
			args:     []string{"--launch-config=" + testLaunchConfig},
			expected: "--ovmf and --launch-config must be used together",
		},
		{
			name:   "absent ovmf",
			report: testReport,
			args: []string{
				"--ovmf=../../data/snp/absent.fd", "--launch-config=" + testLaunchConfig},
			expected: "error loading OVMF from",
		},
		{
			// a report is not a launch config
			name:   "bad launch config",
			report: testReport,
			args: []string{
				"--ovmf=" + testOVMF, "--launch-config=" + testReport},
			expected: "error decoding launch configuration from",
		},
		{
			// the direct boot parameters change a computed launch
			// measurement; they cannot be applied to the one already
			// in the report
			name:   "kernel without ovmf",
			report: testReport,
			args:   []string{"--kernel=" + testEmptyKernel},
			expected: "--kernel only applies when a launch measurement is computed, " +
				"so it needs --ovmf and --launch-config",
		},
		{
			name:   "initrd without ovmf",
			report: testReport,
			args:   []string{"--initrd=" + testEmptyKernel},
			expected: "--initrd only applies when a launch measurement is computed, " +
				"so it needs --ovmf and --launch-config",
		},
		{
			name:   "append without ovmf",
			report: testReport,
			args:   []string{"--append=console=ttyS0"},
			expected: "--append only applies when a launch measurement is computed, " +
				"so it needs --ovmf and --launch-config",
		},
		{
			// an initrd or a command line without a kernel would be
			// dropped from the measurement without a word, since the
			// hashes table is keyed off the kernel
			name:   "initrd without a kernel",
			report: testReport,
			args: []string{
				"--ovmf=" + testDirectBootOVMF, "--launch-config=" + testDirectBootConfig,
				"--initrd=" + testEmptyKernel},
			expected: "--initrd is only measured alongside a directly booted kernel, " +
				"so it needs --kernel",
		},
		{
			name:   "append without a kernel",
			report: testReport,
			args: []string{
				"--ovmf=" + testDirectBootOVMF, "--launch-config=" + testDirectBootConfig,
				"--append=console=ttyS0"},
			expected: "--append is only measured alongside a directly booted kernel, " +
				"so it needs --kernel",
		},
		{
			name:   "absent kernel",
			report: testReport,
			args: []string{
				"--ovmf=" + testOVMF, "--launch-config=" + testLaunchConfig,
				"--kernel=../../data/snp/absent.img"},
			expected: "error loading kernel from ../../data/snp/absent.img",
		},
		{
			name:   "absent initrd",
			report: testReport,
			args: []string{
				"--ovmf=" + testOVMF, "--launch-config=" + testLaunchConfig,
				"--kernel=" + testEmptyKernel, "--initrd=../../data/snp/absent.img"},
			expected: "error loading initrd from ../../data/snp/absent.img",
		},
		{
			// firmware without an SNP_KERNEL_HASHES section cannot
			// measure a kernel, and has to say so rather than quietly
			// producing a measurement that ignores it
			name:   "firmware that cannot measure a kernel",
			report: testReport,
			args: []string{
				"--ovmf=" + testOVMF, "--launch-config=" + testLaunchConfig,
				"--kernel=" + testEmptyKernel, "--append=console=ttyS0"},
			expected: "OVMF metadata doesn't include SNP_KERNEL_HASHES section",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			_, err := generate(t, append([]string{tv.report}, tv.args...)...)
			assert.ErrorContains(t, err, tv.expected)
		})
	}
}

// The launch measurement of a directly booted kernel, checked against the value
// the reference implementation produces. sev-snp-measure-go's own test suite
// derives this digest from sev-snp-measure.py for the same inputs, so matching
// it shows that gen-corim drives the computation the way the reference tool
// does - the guest features, VMM type and vCPU count it passes included.
func Test_Generate_direct_boot_matches_the_reference_implementation(t *testing.T) {
	payloads, err := generate(t, testReport,
		"--ovmf="+testDirectBootOVMF, "--launch-config="+testDirectBootConfig,
		"--kernel="+testEmptyKernel, "--initrd="+testEmptyKernel,
		"--append=console=ttyS0 loglevel=7")
	require.NoError(t, err)
	require.Len(t, payloads[0].Comids, 1)

	want, err := hex.DecodeString(referenceLaunchDigest)
	require.NoError(t, err)

	assert.Equal(t, want, launchMeasurementOf(t, payloads[0].Comids[0]))
}

// Guest features other than the default reach the computation, checked against
// the reference implementation as above. The second case has them apply to every
// vCPU count rather than only to the first CoMID.
func Test_Generate_guest_features_match_the_reference_implementation(t *testing.T) {
	t.Run("one vCPU with a command line", func(t *testing.T) {
		config := writeLaunchConfig(t,
			`{"max-vcpus": 1, "cpu-model": "EPYC-v4", "guest-features": "0x21"}`)

		payloads, err := generate(t, testReport,
			"--ovmf="+testDirectBootOVMF, "--launch-config="+config,
			"--kernel="+testEmptyKernel, "--initrd="+testEmptyKernel,
			"--append=console=ttyS0 loglevel=7")
		require.NoError(t, err)
		require.Len(t, payloads[0].Comids, 1)

		want, err := hex.DecodeString(referenceDigestFeatures0x21)
		require.NoError(t, err)

		assert.Equal(t, want, launchMeasurementOf(t, payloads[0].Comids[0]))
	})

	t.Run("four vCPUs", func(t *testing.T) {
		config := writeLaunchConfig(t,
			`{"max-vcpus": 4, "cpu-model": "EPYC-v4", "guest-features": "0x21"}`)

		payloads, err := generate(t, testReport,
			"--ovmf="+testDirectBootOVMF, "--launch-config="+config,
			"--kernel="+testEmptyKernel, "--initrd="+testEmptyKernel)
		require.NoError(t, err)
		require.Len(t, payloads[0].Comids, 4)

		want, err := hex.DecodeString(referenceDigestFeatures0x21FourVCPUs)
		require.NoError(t, err)

		// the reference digest is the four-vCPU one, so the last CoMID
		assert.Equal(t, want, launchMeasurementOf(t, payloads[0].Comids[3]))
	})
}

// Guest features and the VMM type are part of what is measured, so changing
// either produces different reference values.
func Test_Generate_launch_config_fields_change_the_measurement(t *testing.T) {
	digestFor := func(t *testing.T, fields string) []byte {
		t.Helper()

		config := writeLaunchConfig(t, `{"max-vcpus": 1, "cpu-model": "EPYC-v4"`+fields+`}`)

		payloads, err := generate(t, testReport,
			"--ovmf="+testOVMF, "--launch-config="+config)
		require.NoError(t, err)
		require.Len(t, payloads[0].Comids, 1)

		return launchMeasurementOf(t, payloads[0].Comids[0])
	}

	base := digestFor(t, "")

	assert.Equal(t, base, digestFor(t, `, "guest-features": "0x1", "vmm-type": "qemu"`),
		"the defaults are the values that were hard coded")
	assert.NotEqual(t, base, digestFor(t, `, "guest-features": "0x21"`))
	assert.NotEqual(t, base, digestFor(t, `, "vmm-type": "ec2"`))
}

// A kernel changes the launch measurement, which is the whole reason for passing
// one. It is also the only case measuring a kernel without an initrd, which
// --initrd being optional allows.
func Test_Generate_kernel_without_an_initrd(t *testing.T) {
	withoutKernel, err := generate(t, testReport,
		"--ovmf="+testDirectBootOVMF, "--launch-config="+testDirectBootConfig)
	require.NoError(t, err)

	withKernel, err := generate(t, testReport,
		"--ovmf="+testDirectBootOVMF, "--launch-config="+testDirectBootConfig,
		"--kernel="+testEmptyKernel)
	require.NoError(t, err)

	assert.NotEqual(t,
		launchMeasurementOf(t, withoutKernel[0].Comids[0]),
		launchMeasurementOf(t, withKernel[0].Comids[0]))
}

func Test_Generate_golden(t *testing.T) {
	for _, tv := range []struct {
		name   string
		args   []string
		golden string
	}{
		{
			name:   "as reported",
			golden: "snp-endorsements.cbor",
		},
		{
			name: "synthesized",
			args: []string{
				"--ovmf=" + testOVMF,
				"--launch-config=" + testLaunchConfig,
			},
			golden: "snp-synthesized-endorsements.cbor",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			fs := afero.NewOsFs()

			s := New()
			flags := newFlagSet(t, s)
			require.NoError(t, flags.Parse(tv.args))

			opts := &generator.Options{
				TemplateDir: testTemplate,
				OutputDir:   t.TempDir(),
				Format:      generator.FormatCBOR,
				Seed:        "golden",
			}

			g, err := generator.New(fs, opts, "snp")
			require.NoError(t, err)

			payloads, err := s.Generate(fs, g, []string{testReport})
			require.NoError(t, err)

			paths, err := g.Write(payloads)
			require.NoError(t, err)
			require.Len(t, paths, 1)

			got, err := afero.ReadFile(fs, paths[0])
			require.NoError(t, err)

			golden := filepath.Join(goldenDir, tv.golden)

			if *update {
				require.NoError(t, fs.MkdirAll(goldenDir, 0755))
				require.NoError(t, afero.WriteFile(fs, golden, got, 0644))
				return
			}

			want, err := afero.ReadFile(fs, golden)
			require.NoError(t, err, "golden file missing; regenerate with -update")
			assert.Equal(t, want, got)

			_, err = corim.UnmarshalAndValidateUnsignedCorimFromCBOR(want)
			assert.NoError(t, err)
		})
	}
}

func Test_LaunchConfig_Valid(t *testing.T) {
	for _, tv := range []struct {
		name     string
		config   LaunchConfig
		expected string
	}{
		{
			name:     "no vcpus",
			config:   LaunchConfig{CPUModel: "EPYC-Milan-v2"},
			expected: "max-vcpus must be at least 1, got 0",
		},
		{
			name:     "negative vcpus",
			config:   LaunchConfig{MaxVCPUs: -1, CPUModel: "EPYC-Milan-v2"},
			expected: "max-vcpus must be at least 1, got -1",
		},
		{
			name:     "no cpu model",
			config:   LaunchConfig{MaxVCPUs: 4},
			expected: "cpu-model not specified",
		},
		{
			name:     "unknown vmm type",
			config:   LaunchConfig{MaxVCPUs: 4, CPUModel: "EPYC-Milan-v2", VMMType: VMMType(7)},
			expected: "unknown vmm-type VMMType(7), want one of ec2, qemu",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			assert.EqualError(t, tv.config.Valid(), tv.expected)
		})
	}
}

// New must hand out independent flag state, so that one command cannot see the
// flags of another: --csp-id on the first instance, which the chip-signed test
// report rejects, must leave the second one without one.
func Test_New_returns_independent_instances(t *testing.T) {
	fs := afero.NewOsFs()

	opts := &generator.Options{TemplateDir: testTemplate, Format: generator.FormatCBOR}
	g, err := generator.New(fs, opts, "snp")
	require.NoError(t, err)

	first := New()
	require.NoError(t, newFlagSet(t, first).Parse([]string{"--csp-id=acme"}))

	second := New()
	require.NoError(t, newFlagSet(t, second).Parse(nil))

	_, err = first.Generate(fs, g, []string{testReport})
	assert.ErrorContains(t, err, "--csp-id does not apply")

	_, err = second.Generate(fs, g, []string{testReport})
	require.NoError(t, err)
}
