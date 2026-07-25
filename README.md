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

Supported schemes are documented below as they are added.

## Developing

```sh
make build     # build
make test      # unit tests
make lint      # golangci-lint
```

## License

Apache 2.0
