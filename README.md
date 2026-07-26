# gen-corim

Generate [CoRIM](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/) endorsements from
attestation evidence.

`gen-corim` reads an attestation token or platform report, extracts the reference values and
attestation verification keys it carries, and emits a CoRIM conforming to the relevant profile.
It uses these libraries directly:

- [corim](https://github.com/veraison/corim) to assemble, validate and sign the CoRIM
- [psatoken](https://github.com/veraison/psatoken) and
  [ccatoken](https://github.com/veraison/ccatoken) to decode PSA and CCA tokens
- [go-sev-guest](https://github.com/google/go-sev-guest) to decode and verify SEV-SNP reports
- [sev-snp-measure-go](https://github.com/virtee/sev-snp-measure-go) to compute SEV-SNP launch
  measurements

Coming from gen-corim v1 or from `go-gen-ref`? See [MIGRATION.md](MIGRATION.md).

## Installing

```sh
go install github.com/veraison/gen-corim@latest
```

## Usage

```sh
gen-corim <scheme> <evidence-file> [flags]
```

| flag | short | default | meaning |
|---|---|---|---|
| `--template-dir` | `-t` | *required* | directory holding the templates |
| `--output-dir` | `-o` | `.` | directory the generated CoRIM is written to |
| `--corim-file` | `-c` | | full output path, only valid when the run produces one CoRIM |
| `--format` | | `cbor` | `cbor` or `json` |
| `--seed` | | | seed the generated ids are derived from; random if unset |
| `--id-prefix` | | | make the generated ids strings of this prefix followed by a UUID |
| `--key` | `-k` | | key or certificate the evidence signature is checked against |
| `--skip-verify` | | `false` | generate without checking the evidence signature |
| `--trust-anchors` | | | anchors the certificate in `--key` is verified to; repeatable |
| `--crl` | | | revocation list checked against that chain; repeatable |
| `--crl-policy` | | `strict` | `strict` or `permissive`, when no `--crl` covers an issuer |

`--output-dir` and `--corim-file` are mutually exclusive, and passing both is an error rather
than one of them being ignored. `--key` is required unless `--skip-verify` is given. Output is
named `<scheme>[-<label>]-endorsements.<format>`, the label telling apart the CoRIMs of a run
that produces several, unless `--corim-file` says otherwise.

### Verification

`--key` is checked one of three ways.

| given | what is checked |
|---|---|
| `--skip-verify` | nothing; the evidence is taken as it stands |
| `--key` alone | the evidence signature, against that key. A certificate is a container for its key and nothing vouches for it |
| `--key` with `--trust-anchors` | the certificate is verified to those anchors, and only then is its key used |

`--trust-anchors` and `--crl` take file paths, in PEM or DER, and may be repeated; a PEM file
may hold several certificates or several lists. The naming and the `strict`/`permissive` split
follow `cocli corim verify`. Under `strict`, an issuer in the chain that no supplied list
covers fails verification; under `permissive`, it is skipped. `--crl-policy` without `--crl`,
and any of the three with `--skip-verify`, are errors rather than flags with no effect.

`--trust-anchors=builtin` names the anchors an evidence format ships for itself, which only
`snp` has. Anchors never come from the OS trust store: the roots of these formats are
published by their vendors.

Every example below runs as written from a clone of this repository.

### Templates

Who created a CoRIM and how long it is valid cannot be derived from evidence. That comes from
the directory named by `--template-dir`.

| file | holds | required |
|---|---|---|
| `corim-template.json` | `entities`, `validity`, `dependent-rims` | always |
| `comid-template.json` | `lang`, `tag-identity.version`, `entities` | always |

Working examples are under [data/templates](data/templates).

- The profile comes from the evidence, so a template carrying a `profile` (or a v1 `profiles`)
  is rejected rather than overridden.
- Triples in `comid-template.json` are ignored. Reference values and attestation verification
  keys always come from the evidence.
- The CoRIM and CoMID ids are generated, so a template carrying a `corim-id` or a
  `tag-identity.id` is rejected. They are random UUIDs, or strings of `--id-prefix` followed by
  one. With `--seed` each is derived from the seed, the scheme and what it identifies, so the
  same seed, evidence and templates give the same bytes for an unsigned CoRIM.

### psa

```sh
gen-corim psa data/psa/psa-evidence.cbor \
	--key=data/keys/es256-pub.json \
	--template-dir=data/templates/psa
```

Generates PSA endorsements under the `tag:arm.com,2025:psa#1.0.0` profile. Each software
component becomes one `psa.software-component` measurement carrying its digest and signer ID,
and `--key` becomes the attestation verification key, paired with the token's instance ID.

`--key` may equally name an IAK certificate, whose chain is verified when `--trust-anchors`
says what to verify it against:

```sh
gen-corim psa data/psa/psa-evidence.cbor \
	--key=iak.pem --trust-anchors=ca.pem \
	--template-dir=data/templates/psa
```

### cca

```sh
gen-corim cca data/cca/tf-rmm/cca_token.cbor \
	--key=data/cca/tf-rmm/cca_platform.pub \
	--template-dir=data/templates/cca
```

A CCA token describes two target environments, the platform and the realm, each has their
own profile. By default it creates `cca-platform-endorsements.cbor` and
`cca-realm-endorsements.cbor`. Use `--part=platform` or `--part=realm` for just one.

| CoRIM | profile | contents |
|---|---|---|
| platform | `tag:arm.com,2025:cca_platform#1.0.0` | one `cca.software-component` per software component, one `cca.platform-config`, and the CPAK as attestation verification key |
| realm | `tag:arm.com,2025:cca_realm#1.0.0` | `cca.rim`, the four `cca.rem0` to `cca.rem3` registers, and `cca.rpv` when the realm has a personalization value |

A realm is identified by its measurements rather than by a key, so the realm CoRIM is
identified by the realm initial measurement and carries no attestation verification key triple.

As with `psa`, `--key` may name a CPAK certificate, whose chain is verified when
`--trust-anchors` says what to verify it against.

### snp

```sh
# describe VMs that have not been launched yet
gen-corim snp data/snp/report.bin --skip-verify \
	--ovmf=data/snp/OVMF_CODE.cc.fd \
	--launch-config=data/snp/launch-config.json \
	--template-dir=data/templates/snp

# describe the machine the report came from
gen-corim snp data/snp/report.bin --skip-verify \
	--template-dir=data/templates/snp
```

Generates AMD SEV-SNP reference values under the `tag:amd.com,2025:snp-corim-profile` profile,
superseding [go-gen-ref](https://github.com/jraman567/go-gen-ref).

| flag | meaning |
|---|---|
| `--ovmf` | OVMF firmware image the VM boots, required to compute a launch measurement |
| `--launch-config`, `-l` | JSON description of the VM, required alongside `--ovmf` |
| `--kernel` | kernel the VM is booted with directly |
| `--initrd` | initrd the VM is booted with, requires `--kernel` |
| `--append` | kernel command line, requires `--kernel` |
| `--csp-id` | identifier of the cloud service provider, for reports signed by a CSP rather than by a chip |

With `--ovmf` and `--launch-config` the launch measurement is computed for every vCPU count
from 1 up to `max-vcpus`, one CoMID each. Without them it is taken from the report as it
stands, in one CoMID. The report already binds the vCPU count, CPU model and firmware of the
machine that produced it, so no launch config is accepted then.

The launch config:

```json
{
	"max-vcpus": 4,
	"cpu-model": "EPYC-Milan-v2",
	"guest-features": "0x21",
	"vmm-type": "qemu"
}
```

`max-vcpus` and `cpu-model` are required, `guest-features` and `vmm-type` default to `"0x1"`
and `"qemu"`. Configs are validated against
[`launch-config.schema.json`](schemes/snp/launch-config.schema.json).

A directly booted kernel needs firmware carrying an `SNP_KERNEL_HASHES` metadata section, so
`--kernel` against firmware without one is an error.

```sh
gen-corim snp data/snp/report.bin --skip-verify \
	--ovmf=data/snp/ovmf-amdsev-suffix.bin \
	--launch-config=data/snp/launch-config-amdsev.json \
	--kernel=data/snp/empty-kernel.img --append="console=ttyS0" \
	--template-dir=data/templates/snp
```

`--key` is a VCEK or VLEK certificate rather than a JWK. An extended report carries its own
certificate table, and where it does the certificate is taken from there and `--key` may be
left out; a bare report carries none, and gen-corim never fetches one, so it has to come from
the AMD key distribution service separately. That is why `--skip-verify` is the usual path
when all you have is `report.bin`.

Unlike the other schemes, `snp` ships trust anchors: the ASK and ARK that AMD publishes for
Milan, Genoa and Turin, both VCEK and VLEK. They are used by default, so a certificate that is
not a KDS-issued endorsement key of a currently valid chain is rejected, and `--trust-anchors`
is only needed for a product line those roots do not cover.

#### Getting the certificates

[snpguest](https://github.com/virtee/snpguest) fetches what a given report needs, deriving the
chip ID and TCB version from the report itself:

```sh
snpguest fetch vcek pem ./certs report.bin   # writes certs/vcek.pem
snpguest fetch ca   pem ./certs -r report.bin # writes certs/ark.pem and certs/ask.pem
snpguest fetch crl  pem ./certs -r report.bin # writes certs/crl.pem
```

Add `-e vlek` to `fetch ca` for a CSP-signed report, which writes `asvk.pem` in place of
`ask.pem`. The certificates then map onto the flags one for one:

```sh
gen-corim snp report.bin --key=./certs/vcek.pem \
	--trust-anchors=./certs/ask.pem --trust-anchors=./certs/ark.pem \
	--crl=./certs/crl.pem \
	--template-dir=data/templates/snp
```

`--trust-anchors` is repeatable and each file may hold more than one certificate, so a KDS
`cert_chain` works just as well as the two files above. On the host,
[snphost](https://github.com/virtee/snphost) does the same jobs for the CPU it runs on -
`snphost fetch ca pem ./certs`, `snphost fetch crl ./certs` - and `snphost export pem
ghcb-certs.bin ./certs` splits a GHCB certificate chain into individual certificates.

Revocation is checked only when `--crl` names a list signed by the AMD root key of that
product line. AMD supersede a VCEK by its TCB version rather than revoking it, so what such a
list can say is that the ASK is no longer good.

## Developing

```sh
make build            # build
make test             # unit tests
make lint             # golangci-lint
make regen-testdata   # regenerate the golden CoRIMs under data/golden
```

The tests compare against golden CoRIMs, so a change in output shape shows up as a diff and has
to be acknowledged with `make regen-testdata`. Every golden file is also re-decoded through
`corim.UnmarshalAndValidateUnsignedCorimFromCBOR`, re-running profile validation independently
of the code that wrote it.

[data/PROVENANCE.md](data/PROVENANCE.md) records where each test vector came from.

### Adding a scheme

Implement [`scheme.Scheme`](scheme/scheme.go) in a package under `schemes/`, then add its
constructor to `DefaultSchemes` in [cmd/schemes.go](cmd/schemes.go). A scheme supplies its
command metadata, its flags, and a `Generate` method returning the CoMIDs to wrap. Template
handling, tag identities, CoRIM assembly, encoding and file naming are all shared.

## License

Apache 2.0
