# gen-corim

Generate [CoRIM](https://datatracker.ietf.org/doc/draft-ietf-rats-corim/) endorsements from
attestation evidence.

`gen-corim` reads an attestation token or platform report, extracts the reference values and
attestation verification keys it carries, and emits a CoRIM conforming to the relevant profile. It
uses the [corim](https://github.com/veraison/corim), [psatoken](https://github.com/veraison/psatoken)
and [ccatoken](https://github.com/veraison/ccatoken) libraries directly - there are no external
tools to install.

## Installing

```sh
go install github.com/veraison/gen-corim@latest
```

## Usage

```sh
gen-corim <scheme> <evidence-file> [flags]
```

Common flags:

| flag | short | default | meaning |
|---|---|---|---|
| `--template-dir` | `-t` | *required* | directory holding `corim-template.json` and `comid-template.json` |
| `--output-dir` | `-o` | `.` | directory the generated CoRIM is written to |
| `--corim-file` | `-c` | | full output path; only valid when the run produces one CoRIM |
| `--format` | | `cbor` | `cbor` or `json` |
| `--seed` | | | seed the generated ids are derived from; random if unset |
| `--id-prefix` | | | make the generated ids strings of this prefix followed by a UUID |

`--output-dir` and `--corim-file` are mutually exclusive: `--corim-file` is the
whole path, so passing both is an error rather than one of them being ignored.

Supported schemes are documented below as they are added.

### psa

```sh
gen-corim psa token.cbor --template-dir=data/templates/psa
```

Generates PSA endorsements under the `tag:arm.com,2025:psa#1.0.0` profile. The
software components of the token become the reference values - one measurement
each, keyed `psa.software-component`, carrying the component digest and its
signer ID.

### cca

```sh
gen-corim cca token.cbor --template-dir=data/templates/cca
```

A CCA token describes two target environments, the platform and the realm, and
each has a CoRIM profile of its own - so this emits two files rather than one.
`--part=platform` or `--part=realm` generates just one of them.

The platform CoRIM, under `tag:arm.com,2025:cca_platform#1.0.0`, carries one
`cca.software-component` measurement per software component and a single
`cca.platform-config` measurement holding the platform configuration.

The realm CoRIM, under `tag:arm.com,2025:cca_realm#1.0.0`, is identified by the
realm initial measurement and carries `cca.rim`, the four `cca.rem0`-`cca.rem3`
extensible registers, and `cca.rpv` when the realm was given a personalization
value. A realm is identified by its measurements rather than by a key, so it has
no attestation verification key triple.

## Developing

```sh
make build     # build
make test      # unit tests
make lint      # golangci-lint
```

## License

Apache 2.0
