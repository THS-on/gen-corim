// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package generator assembles the CoMIDs produced by an attestation scheme into
// CoRIMs and writes them out. Everything in here is scheme-independent.
package generator

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/gen-corim/scheme"
	"github.com/veraison/swid"
)

// Generator turns scheme payloads into CoRIM files. It implements
// scheme.ComidBuilder so that the schemes it drives obtain their CoMIDs from it.
type Generator struct {
	fs   afero.Fs
	opts *Options
	// name is the sub-command name, used as the base of the output filename.
	name string
	tmpl *templates
	// minted counts the CoMIDs handed out per profile, which is what tells
	// apart the seeded ids of CoMIDs sharing one.
	minted map[string]int
}

// New instantiates a Generator for the named scheme, loading the templates from
// the directory named in opts.
func New(fs afero.Fs, opts *Options, name string) (*Generator, error) {
	if err := opts.Valid(); err != nil {
		return nil, err
	}

	tmpl, err := loadTemplates(fs, opts.TemplateDir)
	if err != nil {
		return nil, err
	}

	return &Generator{fs: fs, opts: opts, name: name, tmpl: tmpl, minted: map[string]int{}}, nil
}

// newID returns a random UUID, or the string of IDPrefix followed by one. With
// a seed the UUID is derived from the seed, the sub-command and the purpose
// naming what the id is for, so that one seed never gives two things one id.
func (o *Generator) newID(purpose ...string) (swid.TagID, error) {
	source := rand.Reader

	if o.opts.Seed != "" {
		key := sha256.Sum256(fmt.Appendf(nil, "%q", append([]string{o.opts.Seed, o.name}, purpose...)))
		source = bytes.NewReader(key[:])
	}

	u, err := uuid.NewRandomFromReader(source)
	if err != nil {
		return swid.TagID{}, fmt.Errorf("error generating an id: %w", err)
	}

	if o.opts.IDPrefix == "" {
		return *swid.NewTagID(u), nil
	}

	// not NewTagID, which would parse a prefix such as "urn:uuid:" back into a UUID
	id, err := swid.NewTagIDFromString(o.opts.IDPrefix + u.String())
	if err != nil {
		return swid.TagID{}, fmt.Errorf("error generating an id: %w", err)
	}

	return *id, nil
}

// NewComid returns a CoMID pre-populated from the CoMID template and with the
// extensions of profileURI registered. The triples carried by the template are
// dropped: reference values and attestation verification keys come from the
// evidence, not from the template.
func (o *Generator) NewComid(profileURI string) (*comid.Comid, error) {
	profileID, err := corim.NewProfileFromString(profileURI)
	if err != nil {
		return nil, fmt.Errorf("invalid profile %q: %w", profileURI, err)
	}

	m := comid.NewComid()

	if profileManifest, ok := corim.GetProfileManifest(profileID); ok {
		m = profileManifest.GetComid()
	}

	metadata, err := comidMetadata(o.tmpl.comid)
	if err != nil {
		return nil, fmt.Errorf("error decoding template %s: %w", ComidTemplateName, err)
	}

	if err = m.FromJSON(metadata); err != nil {
		return nil, fmt.Errorf("error decoding template %s: %w", ComidTemplateName, err)
	}

	n := o.minted[profileURI]
	o.minted[profileURI]++

	if m.TagIdentity.TagID, err = o.newID("comid", profileURI, strconv.Itoa(n)); err != nil {
		return nil, err
	}

	return m, nil
}

// Write assembles one CoRIM per payload and writes it out, returning the paths
// of the files written.
func (o *Generator) Write(payloads []scheme.Payload) ([]string, error) {
	if len(payloads) == 0 {
		return nil, fmt.Errorf("no CoRIM to write")
	}

	if o.opts.CorimFile != "" && len(payloads) > 1 {
		return nil, fmt.Errorf(
			"--corim-file cannot be used when %d CoRIMs are generated; use --output-dir",
			len(payloads),
		)
	}

	paths := make([]string, 0, len(payloads))

	for i := range payloads {
		path, err := o.writeOne(&payloads[i])
		if err != nil {
			return nil, err
		}

		paths = append(paths, path)
	}

	return paths, nil
}

func (o *Generator) writeOne(payload *scheme.Payload) (string, error) {
	uc, err := o.assemble(payload)
	if err != nil {
		return "", err
	}

	data, err := o.encode(uc)
	if err != nil {
		return "", err
	}

	path := o.outputPath(payload.Label)

	// the output location is the caller's intent rather than a precondition
	if dir := filepath.Dir(path); dir != "" {
		if err := o.fs.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("error creating %s: %w", dir, err)
		}
	}

	if err := afero.WriteFile(o.fs, path, data, 0644); err != nil {
		return "", fmt.Errorf("error writing %s: %w", path, err)
	}

	return path, nil
}

func (o *Generator) outputPath(label string) string {
	if o.opts.CorimFile != "" {
		return o.opts.CorimFile
	}

	name := o.name
	if label != "" {
		name += "-" + label
	}

	return filepath.Join(o.opts.OutputDir, name+"-endorsements."+o.opts.Format)
}

func (o *Generator) assemble(payload *scheme.Payload) (*corim.UnsignedCorim, error) {
	if len(payload.Comids) == 0 {
		return nil, fmt.Errorf("no CoMID in the %q payload", payload.Profile)
	}

	profileID, err := corim.NewProfileFromString(payload.Profile)
	if err != nil {
		return nil, fmt.Errorf("invalid profile %q: %w", payload.Profile, err)
	}

	uc := corim.GetUnsignedCorim(profileID)

	metadata, err := corimMetadata(o.tmpl.corim)
	if err != nil {
		return nil, fmt.Errorf("error decoding template %s: %w", CorimTemplateName, err)
	}

	if err = uc.FromJSON(metadata); err != nil {
		return nil, fmt.Errorf("error decoding template %s: %w", CorimTemplateName, err)
	}

	// The profile is a property of the evidence, not of the template - which
	// cannot state one of its own, readTemplate having refused it at load.
	uc.Profile = profileID

	if uc.ID, err = o.newID("corim", payload.Profile, payload.Label); err != nil {
		return nil, err
	}

	for _, m := range payload.Comids {
		if uc.AddComid(m) == nil {
			return nil, fmt.Errorf("error adding CoMID to the %q CoRIM", payload.Profile)
		}
	}

	// ToJSON, unlike ToCBOR, does not validate
	if err = uc.Valid(); err != nil {
		return nil, fmt.Errorf("error validating the %q CoRIM: %w", payload.Profile, err)
	}

	return uc, nil
}

func (o *Generator) encode(uc *corim.UnsignedCorim) ([]byte, error) {
	if o.opts.Format == FormatJSON {
		data, err := uc.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("error encoding CoRIM to JSON: %w", err)
		}

		return data, nil
	}

	data, err := uc.ToCBOR()
	if err != nil {
		return nil, fmt.Errorf("error encoding CoRIM to CBOR: %w", err)
	}

	return data, nil
}
