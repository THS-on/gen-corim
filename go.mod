module github.com/veraison/gen-corim

go 1.26.4

// Note on the veraison/corim version: the pseudo-version below looks like a v1
// but is in fact corim v2 (tag v2.0.0-rc2 plus later commits on main). The v2
// tags sit on a module path that has no /v2 suffix, so the go tool ignores them
// and derives the pseudo-version from the newest v1 tag instead. Do not
// "correct" it to a v1.1.x release: that would be a downgrade to the pre-profile
// API. The same applies to veraison/psatoken.
require (
	github.com/google/uuid v1.3.0 // indirect
	github.com/spf13/afero v1.15.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
	github.com/stretchr/testify v1.11.1
	github.com/veraison/corim v1.1.3-0.20260702145645-53b3014ea996
	github.com/veraison/swid v1.1.1-0.20251003121634-fd1f7f1e1897 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.8.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/veraison/eat v0.0.0-20210331113810-3da8a4dd42ff // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/text v0.28.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
