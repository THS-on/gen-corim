// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
)

// Names of the template files expected in the template directory.
const (
	CorimTemplateName = "corim-template.json"
	ComidTemplateName = "comid-template.json"
	MetaTemplateName  = "meta-template.json"
)

type templates struct {
	corim []byte
	comid []byte
	meta  []byte
}

// loadTemplates reads the templates from dir. The CoRIM meta template is only
// required, and only read, when the CoRIM is to be signed.
func loadTemplates(fs afero.Fs, dir string, needMeta bool) (*templates, error) {
	exists, err := afero.DirExists(fs, dir)
	if err != nil {
		return nil, fmt.Errorf("error accessing template directory %s: %w", dir, err)
	}

	if !exists {
		return nil, fmt.Errorf("template directory %s does not exist", dir)
	}

	var t templates

	if t.corim, err = readTemplate(fs, dir, CorimTemplateName); err != nil {
		return nil, err
	}

	if t.comid, err = readTemplate(fs, dir, ComidTemplateName); err != nil {
		return nil, err
	}

	if needMeta {
		if t.meta, err = readTemplate(fs, dir, MetaTemplateName); err != nil {
			return nil, err
		}
	}

	return &t, nil
}

// comidMetadata strips the triples from a CoMID template, leaving the metadata
// that cannot be derived from evidence. An empty triples field is substituted
// rather than removed, since it is mandatory in a CoMID: that lets a template
// hold metadata alone. The tag identity is mandatory too, and since its id is
// generated a template may leave it out altogether.
func comidMetadata(template []byte) ([]byte, error) {
	var fields map[string]json.RawMessage

	if err := json.Unmarshal(template, &fields); err != nil {
		return nil, err
	}

	fields["triples"] = json.RawMessage(`{}`)

	if _, ok := fields["tag-identity"]; !ok {
		fields["tag-identity"] = json.RawMessage(`{}`)
	}

	return json.Marshal(fields)
}

// corimMetadata substitutes a stand-in for the corim-id that the corim library
// requires when decoding a CoRIM template. The generated id replaces it.
func corimMetadata(template []byte) ([]byte, error) {
	var fields map[string]json.RawMessage

	if err := json.Unmarshal(template, &fields); err != nil {
		return nil, err
	}

	fields["corim-id"] = json.RawMessage(`"generated"`)

	return json.Marshal(fields)
}

// A forbiddenField is a template field, dotted when nested, that the generator
// sets itself. A template carrying one is rejected rather than overridden in
// silence.
type forbiddenField struct {
	key    string
	reason string
}

const (
	generatedID         = "ids are generated (see --seed and --id-prefix)"
	profileFromEvidence = "the profile comes from the evidence"
)

var forbiddenFields = map[string][]forbiddenField{
	CorimTemplateName: {
		{"corim-id", generatedID},
		// "profiles" is the v1 spelling, and a v1 template the likeliest
		// source of either
		{"profile", profileFromEvidence},
		{"profiles", profileFromEvidence},
	},
	ComidTemplateName: {{"tag-identity.id", generatedID}},
}

func readTemplate(fs afero.Fs, dir, name string) ([]byte, error) {
	path := filepath.Join(dir, name)

	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("error loading template %s: %w", path, err)
	}

	var fields map[string]json.RawMessage

	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return nil, fmt.Errorf("error decoding template %s: %w", path, err)
		}

		return nil, fmt.Errorf("template %s must be a JSON object", path)
	}

	for _, field := range forbiddenFields[name] {
		if hasField(fields, field.key) {
			return nil, fmt.Errorf("template %s must not set %q: %s, so remove the field",
				path, field.key, field.reason)
		}
	}

	return data, nil
}

func hasField(fields map[string]json.RawMessage, key string) bool {
	head, rest, nested := strings.Cut(key, ".")

	value, ok := fields[head]
	if !ok || !nested {
		return ok
	}

	var inner map[string]json.RawMessage

	return json.Unmarshal(value, &inner) == nil && hasField(inner, rest)
}
