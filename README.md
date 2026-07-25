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

## Developing

```sh
make build     # build
make test      # unit tests
make lint      # golangci-lint
```

## License

Apache 2.0
