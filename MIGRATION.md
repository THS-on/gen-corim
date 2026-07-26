# Migrating to gen-corim v2

gen-corim was rewritten to call the CoRIM libraries directly rather than driving
`evcli` and `cocli` as subprocesses, and to absorb the SEV-SNP support that lived
in a separate tool. This is what changes for existing users of either.

## From gen-corim v1

The old tool drove `evcli` and `cocli` as subprocesses; this one calls the
libraries, so neither has to be installed any more.

| v1 | now |
|---|---|
| `gen-corim psa evidence.cbor key.json -t templates` | `gen-corim psa evidence.cbor -k key.json -t templates` |
| the key was the third positional argument | it is the `--key`/`-k` flag |
| `cca` produced one CoRIM | `cca` produces two, one per profile; see `--part` |
| templates targeted corim v1 | templates target the v2 profiles, and must not set `profile` |
| templates set `corim-id` and `tag-identity.id` | ids are generated, and a template setting one is rejected; `--seed` makes them reproducible |

The output shape changed with corim v2, not just the command line. A PSA
measurement is now keyed by the string `psa.software-component` instead of a
`psa-refval-id`, and the signer ID travels in the measurement's `cryptokeys`.
Templates and any consumers of the generated CoRIMs need updating accordingly.

Three smaller changes worth knowing about:

- A `corim-template.json` naming a profile is rejected. v1 templates set
  `profiles`, and the profile is now taken from the evidence, so a template that
  states one is an error naming the file rather than a field silently
  overridden. Delete it from the template.
- CCA software component versions are dropped. corim's CCA platform validator
  cannot accept a version in either form - it reads the version scheme through a
  nil pointer when it is absent, and rejects the measurement when it is present -
  so the field is omitted until that is fixed upstream.
- A token that contradicts itself about its hash algorithm is now rejected.
  ccatoken checks only that the realm `hash-alg-id` claim is a non-empty string
  and never cross-checks it against the measurements, so a token can name
  SHA-256 while carrying 64 byte ones. Both halves come from the same attester
  and one of them is wrong, so gen-corim reports the contradiction instead of
  picking a side. The `cca-evidence.cbor` vector from the old repository is one
  such token: its realm part no longer generates, though its platform part -
  which is consistent - still does.

## From go-gen-ref

```sh
# before
go-gen-ref sevsnp -r report.bin -c vmconfig.yaml -o OVMF_CODE.fd -f out.cbor

# now
gen-corim snp report.bin --launch-config=launch.json --ovmf=OVMF_CODE.fd \
	--corim-file=out.cbor --template-dir=templates --skip-verify
```

| go-gen-ref | now | why |
|---|---|---|
| `-r`/`--report` | positional argument | every scheme reads `gen-corim <scheme> <input>` |
| `-c` vmconfig, `-f` output | `-l` launch config, `-c` output | `-c` is the output everywhere, as in gen-corim v1 |
| `-o`/`--ovmf` | `--ovmf` | `-o` is the output directory |
| `vmconfig.yaml` | `launch-config.json` | JSON, like the templates; `maxvcpus`/`model` become `max-vcpus`/`cpu-model` |
| guest features and VMM fixed at `0x1` and QEMU | optional `guest-features` and `vmm-type` | go-gen-ref could only describe VMs launched that way; those are still the defaults |
| `cspId` in the config | `--csp-id` | it labels the environment, never a measurement, so it applies in both modes |
| no CoRIM metadata | `--template-dir` | entities and validity come from templates; ids stay random unless `--seed` is given |
| no verification | `--key`/`--skip-verify` | the report signature is checked against a VCEK |
