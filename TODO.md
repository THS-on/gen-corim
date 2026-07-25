# Known gaps and follow-ups

Things deliberately left as they are, recorded so they are not rediscovered from
scratch. Each says what it is, where it lives, and what it would take to close.

## Silent fallbacks

gen-corim tries not to paper over contradictions in its inputs: a token that
names a hash algorithm disagreeing with its own measurements is rejected rather
than reinterpreted (see `scheme/digest.go`). The cases below have not had the
same treatment yet. There is also no warning channel - every situation is either
a hard error or silence - which is why "that flag had no effect" has nowhere to
go.

Roughly in order of how badly each would mislead someone.

### 1. CCA software component versions are dropped

`schemes/cca/platform.go`, `platformMeasurements`. The attester stated a version
and it does not reach the CoRIM. This is a workaround for the corim bug in the
upstream section below, not a choice; there is a code comment and a note in
MIGRATION.md, but nothing at runtime.

Suggested: a warning on stderr while the workaround stands, and removal of both
once corim is fixed.

### 2. Triples in `comid-template.json` are dropped

`generator/template.go`, `comidMetadata`. Reference values and attestation
verification keys always come from the evidence, so a template carrying its own
has them discarded. Documented in the README, silent at runtime.

Suggested: leave as is, or warn. Not an error - the templates shipped under
`data/templates` would be tedious to keep triple-free otherwise.

### 3. `GetHashAlgID` errors are discarded

`schemes/cca/platform.go` and `schemes/cca/realm.go`. Both do
`hashAlgID, _ := claims.GetHashAlgID()`. For the realm this is a *mandatory*
claim whose getter also reports a malformed value, and discarding that would
fall back to inferring the algorithm from the digest length.

Unreachable today: `ccatoken.DecodeAndValidateEvidenceFromCBOR` rejects both a
missing and a malformed claim before we see it. The `_` hides an error class
rather than recording why it cannot happen.

Suggested: propagate the error, or comment why it is impossible.

### Checked and left alone

- PSA's `GetMeasurementType`, `GetMeasurementDesc` and `GetVersion` can only
  return `ErrOptionalFieldMissing` (`psatoken/swcomponent.go`), so the
  `err == nil` guards in `schemes/psa/psa.go` cannot swallow a real error.
  psatoken offers `FilterError` for the general case; it is not needed here.
- `realm.GetPersonalizationValue` is mandatory in ccatoken, so a token without
  one never decodes and the optional-RPV branch in `schemes/cca/realm.go` is
  effectively dead. Harmless, but not the optionality the CoRIM profile
  describes.

## Deferred while implementing

Scope deliberately left out, or done the short way. Not defects, but not
finished either.

### Evidence we read and do not emit

The PSA `certification-reference` claim has a home in the profile -
`corim/profiles/psa`, `MvalExtensions.PsaCertNum`, CBOR key 100 - and nothing
puts it there. Both TF-M vectors carry one (`0604565272829-10010`), so this is
exercisable today, not hypothetical.

Closing it: read `claims.GetCertificationReference()` in
`schemes/psa/psa.go` and register the extension on the measurement. Worth
checking the other profiles for the same shape of omission at the same time.

### A CCA or PSA token can carry its own certificate

`--key`, or nothing: unlike an SNP report, whose certificate table is read where
it has one, the CCA and PSA schemes take the certificate only from the flag.
[draft-ffm-rats-cca-token](https://datatracker.ietf.org/doc/draft-ffm-rats-cca-token/)
says a certified CPAK is identified by an `x5t` thumbprint in the COSE protected
header, with the certificate itself - and any that endorse it - travelling in
`x5chain` in the unprotected header, and that using one requires the CCA
platform profile claim to differ from the reference value.

Closing it: read `x5chain` in `schemes/cca` and `schemes/psa`, use it as the
leaf where `--key` is absent, and reject a `--key` that contradicts it, as
`schemes/snp/verify.go` already does for the certificate table.

What comes *out* needs no change:
[draft-ydb-rats-cca-endorsements](https://www.ietf.org/archive/id/draft-ydb-rats-cca-endorsements-02.html)
requires the CPAK to reach the CoRIM as a `tagged-pkix-base64-key-type` - a
PEM-encoded SubjectPublicKeyInfo, one per triple - which is what
`keyutil.PKIXBase64Key` emits from the certificate's key.

.

### corim's chain revocation is not exported

`scheme/verify.go` reimplements `checkChainRevocation` and
`filterCRLsForIssuer` from `corim/x509chain.go`, which are unexported and only
reachable through `SignedCorim.VerifyWithX5Chain`. The semantics are copied
deliberately, so that `--crl-policy` means here what it means to
`cocli corim verify`.

Closing it: have corim export a chain-level helper, then drop ours.

## Test gaps

- **No end-to-end command test.** `cmd` is tested with a fake scheme, and each
  real scheme is driven through the generator API inside its own package. Nothing
  runs `gen-corim psa <vector>` through cobra with `DefaultSchemes` wired up. The
  README commands were checked by hand, so a break in that wiring would not fail
  the build.
- **Goldens cover a subset.** `data/golden` holds psa-evidence, the tf-rmm CCA
  pair and the two SNP modes. The TF-M vectors, the legacy CCA vector, and the
  JSON and signed outputs are exercised but never compared byte for byte.
- **No SNP report is ever verified successfully.** `schemes/snp` covers the
  `--key` error paths - an absent certificate, a bare key in place of one, and a
  certificate AMD did not issue - but not the accepting path, which needs a real
  VCEK from the AMD key distribution service and a `data/PROVENANCE.md` entry to
  go with it. PSA and CCA both verify their vectors, with and without a chain.

  The same gap keeps the SNP trust anchor and revocation handling at unit level:
  a certificate carrying KDS extensions cannot be minted in a test, so
  `rootsFromFiles` and `applyCRLs` are driven directly rather than through a
  report. Nothing exercises `productLine` on a v3 report, or the VLEK bundles.

## Upstream

### corim: CCA platform validator dereferences a nil version scheme

`profiles/cca/platform.go`, `validateCCASoftwareComponent`, reads
`Val.Ver.Scheme.String()` without a nil check. `swid.VersionScheme.String()` has
a value receiver, so an absent scheme panics - and a present one is rejected,
because the profile forbids it. A `cca.software-component` can therefore carry
no version in either form, which is why item 1 above exists.

Closing it: fix upstream, then drop the `measurement.Val.Ver = nil` in
`schemes/cca/platform.go` and the note in MIGRATION.md.

### corim: `Triples.AddAttestVerifKey` dereferences a nil slice

Unlike `Comid.AddAttestVerifKey`, the `Triples` method does not create the list
first. We use the `Comid` wrappers throughout, which is the right thing anyway;
noted so the reason is not mistaken for style.

### sev-snp-measure-go: an OVMF image can only be read from a path

`ovmf.New` takes a filename and opens it itself, so `--ovmf` always resolves
against the real filesystem while everything else goes through the `afero.Fs`
the command was given (`schemes/snp/launchconfig.go`, `launchDigests`). It means
the SNP tests cannot use an in-memory filesystem the way the generator tests do.

Closing it: add an `ovmf.NewFromBytes`, or similar, upstream - `New` already
reads the whole file before parsing it, so it becomes a wrapper around the new
constructor - then read the image with `afero.ReadFile` here and drop the note
above `launchDigests`.
