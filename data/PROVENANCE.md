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

## Derived

| local | derived from | how |
|---|---|---|
| `keys/wrong-es256.json` | `testAltIAK` in [veraison/ccatoken](https://github.com/veraison/ccatoken) `test_common.go` (`cfb829e`) | the JWK literal extracted into a file |

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
