// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/veraison/gen-corim/generator"
	"github.com/veraison/gen-corim/scheme"
)

// Version is the version of the gen-corim command. It may be overridden at
// build time with -ldflags="-X github.com/veraison/gen-corim/cmd.Version=...".
var Version = "0.1.0"

// NewRootCmd instantiates the gen-corim root command, adding one sub-command
// per supplied scheme factory.
func NewRootCmd(fs afero.Fs, factories ...scheme.Factory) *cobra.Command {
	opts := &generator.Options{}

	cmd := &cobra.Command{
		Use:   "gen-corim <scheme> <evidence-file> [flags]",
		Short: "generate CoRIM from supplied evidence",
		Long: `Generate a CoRIM from an attestation token or platform report.

Each supported attestation scheme is a sub-command taking the evidence as its
only positional argument. Metadata that cannot be derived from the evidence -
the entities, the validity period - is read from the templates in the directory
given by --template-dir. CoRIM and CoMID ids are generated, and are random
unless --seed is given.
`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	flags := cmd.PersistentFlags()

	flags.StringVarP(&opts.TemplateDir, "template-dir", "t", "",
		"directory containing the CoRIM and CoMID templates")
	flags.StringVarP(&opts.OutputDir, "output-dir", "o", ".",
		"directory the generated CoRIM is written to")
	flags.StringVarP(&opts.CorimFile, "corim-file", "c", "",
		"full path of the generated CoRIM; only valid when one CoRIM is produced")
	flags.StringVar(&opts.Format, "format", generator.FormatCBOR,
		"encoding of the generated CoRIM, either cbor or json")
	flags.StringVar(&opts.Seed, "seed", "",
		"seed the generated ids are derived from, making unsigned output reproducible; random if unset")
	flags.StringVar(&opts.IDPrefix, "id-prefix", "",
		"prefix turning the generated ids from UUIDs into strings of the prefix followed by a UUID")

	// --corim-file is the full output path, so it has no use for a directory.
	cmd.MarkFlagsMutuallyExclusive("output-dir", "corim-file")

	for _, newScheme := range factories {
		cmd.AddCommand(newSchemeCmd(fs, opts, newScheme()))
	}

	return cmd
}

func newSchemeCmd(fs afero.Fs, opts *generator.Options, s scheme.Scheme) *cobra.Command {
	cmd := &cobra.Command{
		Use:           s.Use(),
		Short:         s.Short(),
		Long:          s.Long(),
		Args:          s.Args(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		g, err := generator.New(fs, opts, cmd.Name())
		if err != nil {
			return err
		}

		payloads, err := s.Generate(fs, g, args)
		if err != nil {
			return err
		}

		paths, err := g.Write(payloads)
		if err != nil {
			return err
		}

		for _, path := range paths {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), ">> generated %q\n", path); err != nil {
				return err
			}
		}

		return nil
	}

	s.AddFlags(cmd.Flags())

	return cmd
}

// Execute runs the gen-corim root command against the OS filesystem.
func Execute() {
	if err := NewRootCmd(afero.NewOsFs(), DefaultSchemes...).Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
