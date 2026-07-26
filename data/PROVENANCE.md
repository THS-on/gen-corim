# Test vector provenance

Every file under `data/` that came from another project is recorded here, so
that it is possible to tell where a vector came from and whether it has gone
stale, without digging through the history. Each commit that brings vectors in
updates this file in the same commit.

## Copied verbatim

| local | source | upstream path | commit | licence |
|---|---|---|---|---|
| `keys/es256-pub.json` | [veraison/gen-corim](https://github.com/veraison/gen-corim) | `data/keys/es256.json` | `519630a` | Apache-2.0 |
| `keys/es256-priv.json` | [veraison/gen-corim](https://github.com/veraison/gen-corim) | `data/keys/ec256.json` | `519630a` | Apache-2.0 |
| `psa/psa-evidence.cbor` | [veraison/gen-corim](https://github.com/veraison/gen-corim) | `data/corims/psa-evidence.cbor` | `519630a` | Apache-2.0 |
| `psa/tfm/psa-iot-1_sign1.bin` | [veraison/psatoken](https://github.com/veraison/psatoken) | `testvectors/tf-m/psa-iot-1_sign1.bin` | `a6e4612` | Apache-2.0 |
| `psa/tfm/psa-2_0_0_sign1.bin` | [veraison/psatoken](https://github.com/veraison/psatoken) | `testvectors/tf-m/psa-2_0_0_sign1.bin` | `a6e4612` | Apache-2.0 |
| `psa/tfm/public.pem` | [veraison/psatoken](https://github.com/veraison/psatoken) | `testvectors/tf-m/public.pem` | `a6e4612` | Apache-2.0 |
| `cca/cca-evidence.cbor` | [veraison/gen-corim](https://github.com/veraison/gen-corim) | `data/corims/cca-evidence.cbor` | `519630a` | Apache-2.0 |
| `cca/tf-rmm/cca_token.cbor` | [veraison/ccatoken](https://github.com/veraison/ccatoken) | `realm/testvectors/tf-rmm/cca_token.cbor` | `cfb829e` | Apache-2.0 |
| `cca/tf-rmm/cca_platform.pub` | [veraison/ccatoken](https://github.com/veraison/ccatoken) | `realm/testvectors/tf-rmm/cca_platform.pub` | `cfb829e` | Apache-2.0 |
| `snp/report.bin` | [jraman567/go-gen-ref](https://github.com/jraman567/go-gen-ref) | `sample/sevsnp/report.bin` | `c942092` | Apache-2.0 |
| `snp/OVMF_CODE.cc.fd` | [jraman567/go-gen-ref](https://github.com/jraman567/go-gen-ref) | `sample/sevsnp/OVMF_CODE.cc.fd` | `c942092` | Apache-2.0 |
| `snp/ovmf-amdsev-suffix.bin` | [THS-on/sev-snp-measure-go](https://github.com/THS-on/sev-snp-measure-go) | `guest/testdata/ovmf_AmdSev_suffix.bin` | `5963a48` | Apache-2.0 |

## Derived

| local | derived from | how |
|---|---|---|
| `keys/wrong-es256.json` | `testAltIAK` in [veraison/ccatoken](https://github.com/veraison/ccatoken) `test_common.go` (`cfb829e`) | the JWK literal extracted into a file |
| `snp/launch-config.json` | `sample/sevsnp/vmconfig.yaml` in [jraman567/go-gen-ref](https://github.com/jraman567/go-gen-ref) (`c942092`) | converted to JSON, `maxvcpus` and `model` renamed to `max-vcpus` and `cpu-model` |
| `snp/launch-config-amdsev.json` | the `success with kernel` case of `guest/guest_test.go` in [THS-on/sev-snp-measure-go](https://github.com/THS-on/sev-snp-measure-go) (`5963a48`) | its vCPU count and CPU model written as a launch config |
| `snp/empty-kernel.img` | the same case, which passes an empty kernel and initrd | an empty file |

## Generated here

`certs/` is minted by [`certs/generate.go`](certs/generate.go), not taken from
anywhere:

```sh
go run data/certs/generate.go
```

| file | what |
|---|---|
| `certs/ca.pem` | self-signed root, `CN=gen-corim test CA` |
| `certs/other-ca.pem` | a second root that issued none of the below |
| `certs/intermediate.pem` | a CA certificate `ca.pem` issued |
| `certs/cert-chain.pem` | `intermediate.pem` then `ca.pem`, as a key distribution service publishes a chain |
| `certs/iak.pem` | certifies the public key of `keys/es256-pub.json`, which signed `psa/psa-evidence.cbor` |
| `certs/cpak.pem` | certifies `cca/tf-rmm/cca_platform.pub`, which signed `cca/tf-rmm/cca_token.cbor` |
| `certs/crl.pem` | revocation list from `ca.pem`, revoking nothing |
| `certs/crl-revoked.pem` | the same, revoking `iak.pem` and `cpak.pem` |
| `certs/other-crl.pem` | revocation list from `other-ca.pem`, which covers no issuer in any chain here |

They are generated because there is nothing to copy: no attestation scheme
publishes an IAK or CPAK certificate. `psatoken` and `ccatoken` ship the signing
keys as bare keys, the chains in `corim` and `cocli` certify a CoRIM *signer*,
the only certificate in the PSA and CCA test data of `veraison/services` is
AMD's ARK-Genoa used as a deliberately wrong trust anchor, and the CCA reference
stack for QEMU signs with a hardcoded raw key
([`plat/qemu/common/qemu_realm_attest_key.c`](https://github.com/ARM-software/arm-trusted-firmware/blob/master/plat/qemu/common/qemu_realm_attest_key.c)).

What the fixtures do carry is real: the certified keys are the ones the token
vectors were actually signed with, so a chain that verifies leads to a token
that verifies. Neither the CCA nor the PSA attestation specifications define an
X.509 profile for these certificates, so the shape is the minimum a chain needs
- `digitalSignature` on the leaf, `keyCertSign` and `cRLSign` on the authorities.
Validity runs to 2046 and the tests pin the instant they check against, so
nothing here starts failing on a date.

## Notes

- The two `es256-*` files are **one key pair**, not two keys: `es256-pub.json` is
  the public half of `es256-priv.json`. Upstream they are named `es256.json` and
  `ec256.json` respectively, which reads as though they were unrelated keys - the
  old gen-corim test suite used `ec256.json` as its "wrong key" case, so it only
  ever exercised a key-*use* mismatch and never a signature mismatch. They are
  renamed here to say what they are, and `wrong-es256.json` supplies a genuinely
  unrelated key for the negative tests.
- `es256-pub.json` carries `"use": "enc"`, which is wrong for a key used to
  verify evidence. It is kept byte-identical to the upstream vector rather than
  corrected; nothing in gen-corim consults the `use` parameter.
- The TF-M vectors are signed by their own key (`psa/tfm/public.pem`) and the
  gen-corim vectors by `keys/es256-*.json`. The two do not verify against each
  other, which the tests rely on to show that the signature check is real.
- The two CCA vectors cover both token encodings that ccatoken accepts:
  `cca/tf-rmm/cca_token.cbor` uses the CMW collection, `cca/cca-evidence.cbor`
  the deprecated one.
- `snp/OVMF_CODE.cc.fd` carries no `SNP_KERNEL_HASHES` metadata section, so it
  cannot measure a directly booted kernel; `snp/ovmf-amdsev-suffix.bin` can, and
  is 4 KB rather than 3.6 MB. The tests use the first for the ordinary launch
  measurement and the second for direct boot.
- The direct boot test asserts an exact digest,
  `6d287813eb5222d770f75005c664e34c204f385ce832cc2ce7d0d6f354454362f390ef83a92046c042e706363b4b08fa`.
  It is the `expectedHash` of the `success with kernel` case in
  sev-snp-measure-go's own `guest/guest_test.go`, which that project derived from
  the reference implementation `sev-snp-measure.py`. Matching it shows gen-corim
  drives the computation the way the reference tool does, guest features, VMM
  type and vCPU count included - not merely that our own output is stable.
- Files under `golden/` are generated by this repository, not copied: they are
  the expected output of the schemes, regenerated with `make regen-testdata`.
