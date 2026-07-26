// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package cca generates CCA endorsements from a CCA attestation token.
package cca

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/veraison/ccatoken"
	"github.com/veraison/corim/comid"
	"github.com/veraison/gen-corim/keyutil"
	"github.com/veraison/gen-corim/scheme"
)

// Parts of a CCA token that can be turned into endorsements. The platform and
// the realm are described by two different CoRIM profiles, so each is a CoRIM
// of its own.
const (
	PartPlatform = "platform"
	PartRealm    = "realm"
	PartBoth     = "both"
)

// Scheme generates CoRIMs from a CCA attestation token.
type Scheme struct {
	scheme.VerifyOptions
	part string
}

// New returns a CCA scheme with its own flag state.
func New() scheme.Scheme {
	return &Scheme{
		VerifyOptions: scheme.NewVerifyOptions(scheme.VerifyConfig{
			KeyUsage:        "CPAK public key or certificate, in JWK, PEM or DER format, used to verify the token",
			SkipVerifyUsage: "do not check the token signature",
		}),
	}
}

func (o *Scheme) Use() string { return "cca <token-file>" }

func (o *Scheme) Short() string { return "generate CCA endorsements from a CCA token" }

func (o *Scheme) Long() string {
	return `Generate CCA endorsements from a CCA attestation token.

A CCA token describes two target environments, the platform and the realm, and
each has its own CoRIM profile. They are therefore emitted as two CoRIMs; use
--part to generate only one of them.

	gen-corim cca token.cbor --key=cpak-pub.pem --template-dir=templates
	gen-corim cca token.cbor --key=cpak-pub.pem --template-dir=templates --part=platform

The software components of the platform token become the reference values of
the platform CoRIM, along with its configuration, and the key supplied with
--key becomes its attestation verification key. The token signature is checked
against that key first, unless --skip-verify is given.

--key may name a CPAK certificate rather than a bare key. Given
--trust-anchors, the certificate is verified to those anchors before its key is
trusted, and --crl checks the chain against a revocation list. Without
--trust-anchors the certificate is only a container for the key, and nothing
vouches for it.

	gen-corim cca token.cbor --key=cpak.pem --trust-anchors=ca.pem \
		--template-dir=templates
`
}

func (o *Scheme) Args() cobra.PositionalArgs { return cobra.ExactArgs(1) }

func (o *Scheme) AddFlags(flags *pflag.FlagSet) {
	o.VerifyOptions.AddFlags(flags)
	flags.StringVar(&o.part, "part", PartBoth,
		"which part of the token to generate endorsements for: platform, realm or both")
}

// Generate decodes the token, verifies it and turns its claims into one CoRIM
// payload per requested part.
func (o *Scheme) Generate(
	fs afero.Fs, b scheme.ComidBuilder, args []string,
) ([]scheme.Payload, error) {
	if err := o.validFlags(); err != nil {
		return nil, err
	}

	token, err := afero.ReadFile(fs, args[0])
	if err != nil {
		return nil, fmt.Errorf("error loading token from %s: %w", args[0], err)
	}

	evidence, err := ccatoken.DecodeAndValidateEvidenceFromCBOR(token)
	if err != nil {
		return nil, fmt.Errorf("error decoding token from %s: %w", args[0], err)
	}

	verifKey, err := o.verificationKey(fs, evidence, args[0])
	if err != nil {
		return nil, err
	}

	var payloads []scheme.Payload

	if o.part == PartPlatform || o.part == PartBoth {
		payload, err := platformPayload(b, evidence, verifKey)
		if err != nil {
			return nil, err
		}

		payloads = append(payloads, *payload)
	}

	if o.part == PartRealm || o.part == PartBoth {
		payload, err := realmPayload(b, evidence)
		if err != nil {
			return nil, err
		}

		payloads = append(payloads, *payload)
	}

	return payloads, nil
}

func (o *Scheme) validFlags() error {
	if o.KeyFile() == "" && !o.SkipVerify() {
		return errors.New("no key supplied: use --key, or --skip-verify to generate from an unverified token")
	}

	switch o.part {
	case PartPlatform, PartRealm, PartBoth:
		return nil
	default:
		return fmt.Errorf("unsupported part %q, want %q, %q or %q",
			o.part, PartPlatform, PartRealm, PartBoth)
	}
}

// verificationKey loads the CPAK, verifies the token with it and returns it in
// the form the attestation verification key triple expects. It returns nil when
// no key was supplied.
func (o *Scheme) verificationKey(
	fs afero.Fs, evidence *ccatoken.Evidence, tokenFile string,
) (*comid.CryptoKey, error) {
	v, err := o.Resolve(fs)
	if err != nil {
		return nil, err
	}

	if v.Key == nil {
		return nil, nil
	}

	if v.Mode == scheme.ModeChain {
		if err = v.VerifyLeaf(time.Now()); err != nil {
			return nil, fmt.Errorf("error verifying the certificate in %s: %w", o.KeyFile(), err)
		}
	}

	if v.Mode != scheme.ModeSkip {
		if err = evidence.Verify(v.Key); err != nil {
			return nil, fmt.Errorf("error verifying token from %s: %w", tokenFile, err)
		}
	}

	return keyutil.PKIXBase64Key(v.Key)
}
