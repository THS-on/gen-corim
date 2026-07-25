// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/gen-corim/scheme"
)

// newTestPayload mints a CoMID from g and wraps it in a payload.
func newTestPayload(t *testing.T, g *Generator, label string) scheme.Payload {
	t.Helper()

	m, err := g.NewComid(TestProfile)
	require.NoError(t, err)
	addTestRefVal(t, m, "ACME")

	return scheme.Payload{Profile: TestProfile, Label: label, Comids: []*comid.Comid{m}}
}

// writeTestRun writes two CoRIMs, the first holding two CoMIDs, so that the run
// draws ids for several CoMIDs and several CoRIMs.
func writeTestRun(t *testing.T, fs afero.Fs, opts *Options) []string {
	t.Helper()

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	platform := newTestPayload(t, g, "platform")
	platform.Comids = append(platform.Comids, newTestPayload(t, g, "").Comids...)

	paths, err := g.Write([]scheme.Payload{platform, newTestPayload(t, g, "realm")})
	require.NoError(t, err)

	return paths
}

// writtenIDs decodes the CoRIMs at paths, validating them, and returns their
// ids along with those of the CoMIDs they carry.
func writtenIDs(t *testing.T, fs afero.Fs, paths []string) []string {
	t.Helper()

	ids := make([]string, 0, len(paths))

	for _, path := range paths {
		data, err := afero.ReadFile(fs, path)
		require.NoError(t, err)

		uc, err := corim.UnmarshalAndValidateUnsignedCorimFromCBOR(data)
		require.NoError(t, err)

		ids = append(ids, uc.GetID())

		for _, tag := range uc.Tags {
			var m comid.Comid
			require.NoError(t, m.FromCBOR(tag.Content))

			ids = append(ids, m.TagIdentity.TagID.String())
		}
	}

	return ids
}

func Test_New_missing_template_dir(t *testing.T) {
	opts := testOptions()
	opts.TemplateDir = "nowhere"

	_, err := New(testFs(t), opts, "test")
	assert.EqualError(t, err, "template directory nowhere does not exist")
}

func Test_New_missing_corim_template(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "templates/"+ComidTemplateName, testComidTemplate, 0644))

	_, err := New(fs, testOptions(), "test")
	assert.ErrorContains(t, err, "error loading template templates/"+CorimTemplateName)
}

func Test_New_missing_comid_template(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "templates/"+CorimTemplateName, testCorimTemplate, 0644))

	_, err := New(fs, testOptions(), "test")
	assert.ErrorContains(t, err, "error loading template templates/"+ComidTemplateName)
}

func Test_New_meta_template_only_needed_when_signing(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "templates/"+CorimTemplateName, testCorimTemplate, 0644))
	require.NoError(t, afero.WriteFile(fs, "templates/"+ComidTemplateName, testComidTemplate, 0644))

	_, err := New(fs, testOptions(), "test")
	assert.NoError(t, err)

	opts := testOptions()
	opts.SigningKey = "key.json"

	_, err = New(fs, opts, "test")
	assert.ErrorContains(t, err, "error loading template templates/"+MetaTemplateName)
}

func Test_New_rejects_invalid_templates(t *testing.T) {
	const generated = "ids are generated (see --seed and --id-prefix), so remove the field"
	const profile = "the profile comes from the evidence, so remove the field"

	for _, tv := range []struct {
		name     string
		template string
		content  string
		expected string
	}{
		{
			name:     "corim-id",
			template: CorimTemplateName,
			content:  `{"corim-id": "5c57e8f4-46cd-421b-91c9-08cf93e13cfc"}`,
			expected: `must not set "corim-id": ` + generated,
		},
		{
			name:     "tag-identity.id",
			template: ComidTemplateName,
			content:  `{"tag-identity": {"id": "acme-tag", "version": 1}}`,
			expected: `must not set "tag-identity.id": ` + generated,
		},
		{
			name:     "profile",
			template: CorimTemplateName,
			content:  `{"profile": "http://example.com/other-profile"}`,
			expected: `must not set "profile": ` + profile,
		},
		{
			name:     "profiles",
			template: CorimTemplateName,
			content:  `{"profiles": ["http://example.com/other-profile"]}`,
			expected: `must not set "profiles": ` + profile,
		},
		{
			name:     "null",
			template: CorimTemplateName,
			content:  `null`,
			expected: "must be a JSON object",
		},
		{
			name:     "array",
			template: ComidTemplateName,
			content:  `[]`,
			expected: "must be a JSON object",
		},
	} {
		t.Run(tv.name, func(t *testing.T) {
			fs := testFs(t)
			require.NoError(t, afero.WriteFile(fs, "templates/"+tv.template, []byte(tv.content), 0644))

			_, err := New(fs, testOptions(), "test")
			assert.EqualError(t, err, "template templates/"+tv.template+" "+tv.expected)
		})
	}
}

func Test_New_malformed_corim_template(t *testing.T) {
	fs := testFs(t)
	require.NoError(t, afero.WriteFile(fs, "templates/"+CorimTemplateName, []byte(`{`), 0644))

	_, err := New(fs, testOptions(), "test")
	assert.ErrorContains(t, err, "error decoding template templates/"+CorimTemplateName)
}

func Test_NewComid_applies_template(t *testing.T) {
	g, err := New(testFs(t), testOptions(), "test")
	require.NoError(t, err)

	m, err := g.NewComid(TestProfile)
	require.NoError(t, err)

	require.NotNil(t, m.Language)
	assert.Equal(t, "en-GB", *m.Language)
	assert.Equal(t, uint(1), m.TagIdentity.TagVersion)
	require.NotNil(t, m.Entities)
	assert.Equal(t, "ACME Ltd.", m.Entities.Values[0].Name.String())
}

func Test_NewComid_drops_template_triples(t *testing.T) {
	fs := testFs(t)

	// a template carrying a reference value that the evidence would not have
	// produced
	src := comid.NewComid()
	addTestRefVal(t, src, "FROM-TEMPLATE")

	triples, err := json.Marshal(src.Triples)
	require.NoError(t, err)
	require.Contains(t, string(triples), "FROM-TEMPLATE")

	tmpl := []byte(`{"triples": ` + string(triples) + `}`)

	require.NoError(t, afero.WriteFile(fs, "templates/"+ComidTemplateName, tmpl, 0644))

	g, err := New(fs, testOptions(), "test")
	require.NoError(t, err)

	m, err := g.NewComid(TestProfile)
	require.NoError(t, err)

	assert.Nil(t, m.Triples.ReferenceValues)
}

func Test_Write_seed_reproduces_the_output(t *testing.T) {
	fs := testFs(t)

	run := func(seed, dir string) []string {
		opts := testOptions()
		opts.Seed = seed
		opts.OutputDir = dir

		return writeTestRun(t, fs, opts)
	}

	first := run("seed", "first")
	second := run("seed", "second")

	for i := range first {
		want, err := afero.ReadFile(fs, first[i])
		require.NoError(t, err)
		got, err := afero.ReadFile(fs, second[i])
		require.NoError(t, err)
		assert.Equal(t, want, got)
	}

	other := run("other seed", "other")
	assert.NotEqual(t, writtenIDs(t, fs, first), writtenIDs(t, fs, other))
}

// One seed must give different things different ids, and an id must not move
// when an unrelated part of the run changes.
func Test_Write_seeded_ids_depend_on_what_they_identify(t *testing.T) {
	const otherProfile = "http://example.com/other-profile"

	type part struct {
		profile, label string
		comids         int
	}

	fs := testFs(t)

	run := func(name, dir string, parts ...part) []string {
		opts := testOptions()
		opts.Seed = "seed"
		opts.OutputDir = dir

		g, err := New(fs, opts, name)
		require.NoError(t, err)

		payloads := make([]scheme.Payload, 0, len(parts))

		for _, p := range parts {
			payload := scheme.Payload{Profile: p.profile, Label: p.label}

			for range p.comids {
				var m *comid.Comid

				m, err = g.NewComid(p.profile)
				require.NoError(t, err)
				addTestRefVal(t, m, "ACME")

				payload.Comids = append(payload.Comids, m)
			}

			payloads = append(payloads, payload)
		}

		paths, err := g.Write(payloads)
		require.NoError(t, err)

		return paths
	}

	base := writtenIDs(t, fs, run("test", "base", part{TestProfile, "x", 1}))

	for _, other := range [][]string{
		writtenIDs(t, fs, run("other", "name", part{TestProfile, "x", 1})),
		writtenIDs(t, fs, run("test", "profile", part{otherProfile, "x", 1})),
	} {
		for _, id := range other {
			assert.NotContains(t, base, id)
		}
	}

	// the label tells apart CoRIMs, whose CoMIDs a profile already does
	label := writtenIDs(t, fs, run("test", "label", part{TestProfile, "y", 1}))
	assert.NotEqual(t, base[0], label[0])

	first := run("test", "first", part{TestProfile, "x", 1}, part{otherProfile, "y", 1})
	second := run("test", "second", part{TestProfile, "x", 2}, part{otherProfile, "y", 1})

	want, err := afero.ReadFile(fs, first[1])
	require.NoError(t, err)
	got, err := afero.ReadFile(fs, second[1])
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func Test_Write_ids_are_unique(t *testing.T) {
	fs := testFs(t)

	// without a seed, two runs must not repeat an id either
	var ids []string

	for _, dir := range []string{"first", "second"} {
		opts := testOptions()
		opts.OutputDir = dir
		ids = append(ids, writtenIDs(t, fs, writeTestRun(t, fs, opts))...)
	}

	seen := make(map[string]bool, len(ids))

	for _, id := range ids {
		assert.False(t, seen[id], "duplicate id %s", id)
		seen[id] = true
	}
}

func Test_Write_id_prefix(t *testing.T) {
	// "urn:uuid:" makes a prefixed id that would parse back as a bare UUID
	for _, prefix := range []string{"acme-", "urn:uuid:"} {
		t.Run(prefix, func(t *testing.T) {
			fs := testFs(t)

			opts := testOptions()
			opts.IDPrefix = prefix

			for _, id := range writtenIDs(t, fs, writeTestRun(t, fs, opts)) {
				suffix, ok := strings.CutPrefix(id, prefix)
				require.True(t, ok, "id %s lacks the prefix", id)

				_, err := uuid.Parse(suffix)
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Write_unsigned_cbor(t *testing.T) {
	fs := testFs(t)

	g, err := New(fs, testOptions(), "test")
	require.NoError(t, err)

	paths, err := g.Write([]scheme.Payload{newTestPayload(t, g, "")})
	require.NoError(t, err)
	require.Equal(t, []string{"out/test-endorsements.cbor"}, paths)

	data, err := afero.ReadFile(fs, paths[0])
	require.NoError(t, err)

	// re-decoding runs the CoRIM validation independently of the code that
	// produced the file
	uc, err := corim.UnmarshalAndValidateUnsignedCorimFromCBOR(data)
	require.NoError(t, err)

	assert.Equal(t, TestProfile, uc.Profile.String())
	assert.Len(t, uc.Tags, 1)
}

func Test_Write_unsigned_json(t *testing.T) {
	fs := testFs(t)

	opts := testOptions()
	opts.Format = FormatJSON

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	paths, err := g.Write([]scheme.Payload{newTestPayload(t, g, "")})
	require.NoError(t, err)
	require.Equal(t, []string{"out/test-endorsements.json"}, paths)

	data, err := afero.ReadFile(fs, paths[0])
	require.NoError(t, err)

	var uc corim.UnsignedCorim
	require.NoError(t, uc.FromJSON(data))
	require.NoError(t, uc.Valid())
	assert.Equal(t, TestProfile, uc.Profile.String())
	assert.Len(t, uc.Tags, 1)
}

// ToJSON does not validate, so the generator has to.
func Test_Write_rejects_an_invalid_corim_as_json(t *testing.T) {
	fs := testFs(t)
	require.NoError(t, afero.WriteFile(fs, "templates/"+CorimTemplateName, []byte(`{
    "validity": {
        "not-before": "2030-01-01T00:00:00Z",
        "not-after": "2020-01-01T00:00:00Z"
    }
}`), 0644))

	opts := testOptions()
	opts.Format = FormatJSON

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	_, err = g.Write([]scheme.Payload{newTestPayload(t, g, "")})
	assert.ErrorContains(t, err, "invalid not-before / not-after")

	exists, err := afero.Exists(fs, "out/test-endorsements.json")
	require.NoError(t, err)
	assert.False(t, exists)
}

func Test_Write_signed(t *testing.T) {
	fs := testFs(t)

	opts := testOptions()
	opts.SigningKey = "key.json"

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	paths, err := g.Write([]scheme.Payload{newTestPayload(t, g, "")})
	require.NoError(t, err)
	require.Equal(t, []string{"out/test-endorsements.cbor"}, paths)

	data, err := afero.ReadFile(fs, paths[0])
	require.NoError(t, err)

	var sc corim.SignedCorim
	require.NoError(t, sc.FromCOSE(data))
	assert.Equal(t, "ACME Ltd.", sc.Meta.Signer.Name)
	assert.Equal(t, TestProfile, sc.UnsignedCorim.Profile.String())
}

func Test_Write_signed_missing_key(t *testing.T) {
	fs := testFs(t)

	opts := testOptions()
	opts.SigningKey = "absent.json"

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	_, err = g.Write([]scheme.Payload{newTestPayload(t, g, "")})
	assert.ErrorContains(t, err, "error loading signing key from absent.json")
}

// New rejects the combination, so the guard in sign is only reachable by an
// in-package caller assembling a Generator itself. It is what lets outputPath
// take the format at face value.
func Test_Write_signed_rejects_a_non_cbor_format(t *testing.T) {
	fs := testFs(t)

	opts := testOptions()
	opts.SigningKey = "key.json"

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	payload := newTestPayload(t, g, "")
	g.opts.Format = FormatJSON

	_, err = g.Write([]scheme.Payload{payload})
	assert.ErrorIs(t, err, errSignedJSON)
}

func Test_Write_multiple_payloads(t *testing.T) {
	fs := testFs(t)

	g, err := New(fs, testOptions(), "test")
	require.NoError(t, err)

	paths, err := g.Write([]scheme.Payload{
		newTestPayload(t, g, "platform"),
		newTestPayload(t, g, "realm"),
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"out/test-platform-endorsements.cbor",
		"out/test-realm-endorsements.cbor",
	}, paths)
}

// The output directory is named on the command line, so it is the caller's
// intent rather than a precondition: it gets created rather than reported as
// missing.
func Test_Write_creates_the_output_directory(t *testing.T) {
	fs := testFs(t)

	opts := testOptions()
	opts.OutputDir = "no/such/directory"

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	paths, err := g.Write([]scheme.Payload{newTestPayload(t, g, "")})
	require.NoError(t, err)

	exists, err := afero.Exists(fs, paths[0])
	require.NoError(t, err)
	assert.True(t, exists)
}

func Test_Write_corim_file_override(t *testing.T) {
	fs := testFs(t)

	opts := testOptions()
	opts.CorimFile = "some/where/else.cbor"

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	paths, err := g.Write([]scheme.Payload{newTestPayload(t, g, "")})
	require.NoError(t, err)
	assert.Equal(t, []string{"some/where/else.cbor"}, paths)
}

func Test_Write_corim_file_rejected_for_multiple_payloads(t *testing.T) {
	fs := testFs(t)

	opts := testOptions()
	opts.CorimFile = "some/where/else.cbor"

	g, err := New(fs, opts, "test")
	require.NoError(t, err)

	_, err = g.Write([]scheme.Payload{
		newTestPayload(t, g, "platform"),
		newTestPayload(t, g, "realm"),
	})
	assert.EqualError(t, err,
		"--corim-file cannot be used when 2 CoRIMs are generated; use --output-dir")
}

func Test_Write_no_payloads(t *testing.T) {
	g, err := New(testFs(t), testOptions(), "test")
	require.NoError(t, err)

	_, err = g.Write(nil)
	assert.EqualError(t, err, "no CoRIM to write")
}

func Test_Write_payload_without_comids(t *testing.T) {
	g, err := New(testFs(t), testOptions(), "test")
	require.NoError(t, err)

	_, err = g.Write([]scheme.Payload{{Profile: TestProfile}})
	assert.EqualError(t, err, `no CoMID in the "http://example.com/test-profile" payload`)
}

func Test_Write_empty_profile(t *testing.T) {
	g, err := New(testFs(t), testOptions(), "test")
	require.NoError(t, err)

	m, err := g.NewComid(TestProfile)
	require.NoError(t, err)
	addTestRefVal(t, m, "ACME")

	_, err = g.Write([]scheme.Payload{{Comids: []*comid.Comid{m}}})
	assert.ErrorContains(t, err, `invalid profile ""`)
}
