// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/veraison/corim/comid"
	"github.com/veraison/swid"
)

// Class identifiers of the two kinds of SEV-SNP target environment, assigned
// under AMD's enterprise arc by section 3.1.1 of the profile draft:
//
//	https://datatracker.ietf.org/doc/html/draft-deeglaze-amd-sev-snp-corim-profile-02#section-3.1.1
const (
	ClassIDByChip = "1.3.6.1.4.1.3704.3.1"
	ClassIDByCsp  = "1.3.6.1.4.1.3704.3.2"
)

// Sizes of the fixed-width report fields, in bytes.
const (
	policyLen       = 8
	familyIDLen     = 16
	imageIDLen      = 16
	vmplLen         = 4
	platformInfoLen = 8
	reportDataLen   = 64
	hostDataLen     = 32
	idKeyDigestLen  = 48
	authorKeyLen    = 48
	reportIDLen     = 32
	reportIDMALen   = 32
	chipIDLen       = 64
)

// environment builds the target environment the report describes. A VCEK-signed
// report identifies itself by its chip ID; a VLEK-signed one, being a cloud
// service provider's, by the CSP ID the caller supplies, since the report itself
// carries no name for it. The two are exclusive, so a CSP ID given for a
// chip-signed report is an error rather than something to drop.
func environment(report *sevsnp.Report, cspID string) (*comid.Environment, error) {
	var env comid.Environment

	// signer_info is a bitfield, not an enumeration: the signing key occupies
	// bits 2-4, above the AUTHOR_KEY_EN and MASK_CHIP_KEY flags.
	signerInfo, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return nil, fmt.Errorf("error parsing the signer info: %w", err)
	}

	switch signerInfo.SigningKey {
	case abi.VcekReportSigner:
		if cspID != "" {
			return nil, errors.New(
				"--csp-id does not apply to a report signed by a chip: it names the environment of a " +
					"report signed by a cloud service provider's VLEK")
		}

		env.Class = comid.NewClassOID(ClassIDByChip)

		// MASK_CHIP_KEY zeroes the chip ID rather than omitting it.
		if !isAllZeros(report.GetChipId()) {
			instance, err := comid.NewBytesInstance(report.GetChipId())
			if err != nil {
				return nil, fmt.Errorf("error creating the chip ID: %w", err)
			}

			env.Instance = instance
		}
	case abi.VlekReportSigner:
		env.Class = comid.NewClassOID(ClassIDByCsp)

		if cspID != "" {
			instance, err := comid.NewBytesInstance([]byte(cspID))
			if err != nil {
				return nil, fmt.Errorf("error creating the CSP ID: %w", err)
			}

			env.Instance = instance
		}
	default:
		// ParseSignerInfo has already rejected the reserved keys, leaving
		// the unsigned report, which endorses nothing.
		return nil, fmt.Errorf("invalid signing key: %s", signerInfo.SigningKey)
	}

	return &env, nil
}

// measurements turns an attestation report into the measurements of a reference
// value. The measurement keys are those of the AMD SEV-SNP CoRIM profile.
//
// launchMeasurement is the value of MKey 641. It is either taken from the report
// itself or computed for a particular vCPU count, depending on how gen-corim was
// invoked.
func measurements(report *sevsnp.Report, launchMeasurement []byte) *comid.Measurements {
	ms := comid.NewMeasurements()

	addHeaderMeasurements(ms, report)
	addBodyMeasurements(ms, report, launchMeasurement)
	addPlatformMeasurements(ms, report)

	return ms
}

// addHeaderMeasurements adds the measurements taken from the fixed header
// fields of the report, MKeys 0 to 7.
func addHeaderMeasurements(ms *comid.Measurements, report *sevsnp.Report) {
	reportVersion := report.GetVersion()

	/* MKey 0: VERSION */
	m0 := comid.MustNewUintMeasurement(uint(0))
	m0.SetVersion(strconv.Itoa(int(reportVersion)), swid.VersionSchemeDecimal)
	ms.Add(m0)

	/* MKey 1: GUEST_SVN */
	m1 := comid.MustNewUintMeasurement(uint(1))
	m1.SetMinSVN(uint64(report.GetGuestSvn()))
	ms.Add(m1)

	/* MKey 2: POLICY */
	m2 := comid.MustNewUintMeasurement(uint(2))
	policy := make([]byte, policyLen)
	binary.BigEndian.PutUint64(policy, report.GetPolicy())
	m2.SetRawValueBytes(policy, nil)
	ms.Add(m2)

	/* MKey 3: FAMILY_ID */
	m3 := comid.MustNewUintMeasurement(uint(3))
	m3.SetRawValueBytes(fixedWidth(report.GetFamilyId(), familyIDLen), nil)
	ms.Add(m3)

	/* MKey 4: IMAGE_ID */
	m4 := comid.MustNewUintMeasurement(uint(4))
	m4.SetRawValueBytes(fixedWidth(report.GetImageId(), imageIDLen), nil)
	ms.Add(m4)

	/* MKey 5: VMPL */
	m5 := comid.MustNewUintMeasurement(uint(5))
	vmpl := make([]byte, vmplLen)
	binary.BigEndian.PutUint32(vmpl, report.GetVmpl())
	m5.SetRawValueBytes(vmpl, nil)
	ms.Add(m5)

	/* MKey 6: CURRENT_TCB */
	m6 := comid.MustNewUintMeasurement(uint(6))
	m6.SetSVN(report.GetCurrentTcb())
	ms.Add(m6)

	/* MKey 7: PLATFORM */
	m7 := comid.MustNewUintMeasurement(uint(7))
	platform := make([]byte, platformInfoLen)
	binary.BigEndian.PutUint64(platform, report.GetPlatformInfo())
	m7.SetRawValueBytes(platform, nil)
	ms.Add(m7)
}

// addBodyMeasurements adds the measurements describing the guest, MKeys 640 to
// 650.
func addBodyMeasurements(ms *comid.Measurements, report *sevsnp.Report, launchMeasurement []byte) {
	/* MKey 640: REPORT_DATA */
	if !isAllZeros(report.GetReportData()) {
		m640 := comid.MustNewUintMeasurement(uint(640))
		m640.SetRawValueBytes(fixedWidth(report.GetReportData(), reportDataLen), nil)
		ms.Add(m640)
	}

	/* MKey 641: MEASUREMENT */
	m641 := comid.MustNewUintMeasurement(uint(641))
	m641.AddDigest(comid.Sha384, launchMeasurement)
	ms.Add(m641)

	/* MKey 642: HOST_DATA */
	if !isAllZeros(report.GetHostData()) {
		m642 := comid.MustNewUintMeasurement(uint(642))
		m642.SetRawValueBytes(fixedWidth(report.GetHostData(), hostDataLen), nil)
		ms.Add(m642)
	}

	/* MKey 643: ID_KEY_DIGEST */
	if !isAllZeros(report.GetIdKeyDigest()) {
		m643 := comid.MustNewUintMeasurement(uint(643))
		m643.SetRawValueBytes(fixedWidth(report.GetIdKeyDigest(), idKeyDigestLen), nil)
		ms.Add(m643)
	}

	/* MKey 644: AUTHOR_KEY_DIGEST */
	if !isAllZeros(report.GetAuthorKeyDigest()) {
		m644 := comid.MustNewUintMeasurement(uint(644))
		m644.SetRawValueBytes(fixedWidth(report.GetAuthorKeyDigest(), authorKeyLen), nil)
		ms.Add(m644)
	}

	/* MKey 645: REPORT_ID */
	if !isAllZeros(report.GetReportId()) {
		m645 := comid.MustNewUintMeasurement(uint(645))
		m645.SetRawValueBytes(fixedWidth(report.GetReportId(), reportIDLen), nil)
		ms.Add(m645)
	}

	/* MKey 646: REPORT_ID_MA */
	if !isAllZeros(report.GetReportIdMa()) {
		m646 := comid.MustNewUintMeasurement(uint(646))
		m646.SetRawValueBytes(fixedWidth(report.GetReportIdMa(), reportIDMALen), nil)
		ms.Add(m646)
	}

	/* MKey 647: REPORTED_TCB */
	m647 := comid.MustNewUintMeasurement(uint(647))
	m647.SetSVN(report.GetReportedTcb())
	ms.Add(m647)

	if report.GetVersion() >= abi.ReportVersion3 {
		f, m, s := abi.FmsFromCpuid1Eax(report.GetCpuid1EaxFms())

		/* MKey 648: CPU_FAM_ID */
		m648 := comid.MustNewUintMeasurement(uint(648))
		m648.SetRawValueBytes([]byte{f}, nil)
		ms.Add(m648)

		/* MKey 649: CPU_MOD_ID */
		m649 := comid.MustNewUintMeasurement(uint(649))
		m649.SetRawValueBytes([]byte{m}, nil)
		ms.Add(m649)

		/* MKey 650: CPUID_STEP */
		m650 := comid.MustNewUintMeasurement(uint(650))
		m650.SetRawValueBytes([]byte{s}, nil)
		ms.Add(m650)
	}
}

// addPlatformMeasurements adds the measurements describing the platform the
// guest runs on, MKeys 3328 and above.
func addPlatformMeasurements(ms *comid.Measurements, report *sevsnp.Report) {
	/* MKey 3328: CHIP_ID */
	if !isAllZeros(report.GetChipId()) {
		m3328 := comid.MustNewUintMeasurement(uint(3328))
		m3328.SetRawValueBytes(fixedWidth(report.GetChipId(), chipIDLen), nil)
		ms.Add(m3328)
	}

	/* MKey 3329: COMMITTED_TCB */
	m3329 := comid.MustNewUintMeasurement(uint(3329))
	m3329.SetSVN(report.GetCommittedTcb())
	ms.Add(m3329)

	/* MKey 3330: CURRENT_VERSION */
	m3330 := comid.MustNewUintMeasurement(uint(3330))
	m3330.SetVersion(fmt.Sprintf("%d.%d.%d",
		report.GetCurrentMajor(),
		report.GetCurrentMinor(),
		report.GetCurrentBuild()), swid.VersionSchemeSemVer)
	ms.Add(m3330)

	/* MKey 3936: COMMITTED_VERSION */
	m3936 := comid.MustNewUintMeasurement(uint(3936))
	m3936.SetVersion(fmt.Sprintf("%d.%d.%d",
		report.GetCommittedMajor(),
		report.GetCommittedMinor(),
		report.GetCommittedBuild()), swid.VersionSchemeSemVer)
	ms.Add(m3936)

	/* MKey 3968: LAUNCH_TCB */
	m3968 := comid.MustNewUintMeasurement(uint(3968))
	m3968.SetSVN(report.GetLaunchTcb())
	ms.Add(m3968)
}

// fixedWidth returns the value in a buffer of exactly n bytes, so that a report
// field always occupies its full width in the generated CoRIM.
func fixedWidth(value []byte, n int) []byte {
	buf := make([]byte, n)
	copy(buf, value)

	return buf
}

func isAllZeros(buf []byte) bool {
	return bytes.Equal(buf, make([]byte, len(buf)))
}
