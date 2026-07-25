module github.com/veraison/gen-corim

go 1.26.4

// Note on the veraison/corim version: the pseudo-version below looks like a v1
// but is in fact corim v2 (tag v2.0.0-rc2 plus later commits on main). The v2
// tags sit on a module path that has no /v2 suffix, so the go tool ignores them
// and derives the pseudo-version from the newest v1 tag instead. Do not
// "correct" it to a v1.1.x release: that would be a downgrade to the pre-profile
// API. The same applies to veraison/psatoken.
require (
	github.com/google/uuid v1.6.0
	github.com/spf13/afero v1.15.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	github.com/stretchr/testify v1.11.1
	github.com/veraison/corim v1.1.3-0.20260702145645-53b3014ea996
	github.com/veraison/swid v1.1.1-0.20251003121634-fd1f7f1e1897
)

require (
	github.com/google/go-sev-guest v0.15.0
	github.com/lestrrat-go/jwx/v2 v2.0.21
	github.com/veraison/ccatoken v1.4.0
	github.com/veraison/psatoken v1.2.1-0.20251211083527-a6e46122bbca
	github.com/virtee/sev-snp-measure-go v0.0.0-20260408174629-fd0cc4c95d62
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0 // indirect
	github.com/fxamacker/cbor/v2 v2.8.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.2 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc v1.0.5 // indirect
	github.com/lestrrat-go/iter v1.0.2 // indirect
	github.com/lestrrat-go/option v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/veraison/eat v0.0.0-20220117140849-ddaf59d69f53 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
