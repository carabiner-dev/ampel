// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/policy"
	"github.com/puerco/ampel/pkg/subject"
	"github.com/puerco/ampel/pkg/verifier"
)

type verifyOptions struct {
	verifier.VerificationOptions
	PolicyFile   string
	SubjectFiles []string
	Format       string
}

// AddFlags adds the flags
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVarP(
		&o.SubjectFiles, "subject", "s", []string{}, "list of files to vertify",
	)

	cmd.PersistentFlags().StringVarP(
		&o.PolicyFile, "policy", "p", "", "policy file",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.AttestationFiles, "attestation", "a", o.AttestationFiles, "additional attestations to read",
	)

	cmd.PersistentFlags().BoolVar(
		&o.AttestResults, "attest-results", o.AttestResults, "write an attestation with the evaluation results to --results-path",
	)

	cmd.PersistentFlags().StringVar(
		&o.ResultsAttestationPath, "results-path", o.ResultsAttestationPath, "path to the evaluation results attestation",
	)

	cmd.PersistentFlags().StringVarP(
		&o.Format, "format", "f", o.Format, "output format",
	)
}

func (o *verifyOptions) Validate() error {
	var errs = []error{}
	if len(o.SubjectFiles) == 0 {
		errs = append(errs, errors.New("no subject files specified"))
	}

	if o.PolicyFile == "" {
		errs = append(errs, errors.New("a polciy file must be defined"))
	}
	return errors.Join(errs...)
}

func addVerify(parentCmd *cobra.Command) {
	opts := verifyOptions{
		VerificationOptions: verifier.NewVerificationOptions(),
		PolicyFile:          "",
		SubjectFiles:        []string{},
	}
	evalCmd := &cobra.Command{
		Short: "check artifacts against a policy",
		Long: fmt.Sprintf(`
%s

Ampel verify checks an artifact (a subject) against a policy file to assert
the policy tenets to be true.

To verify an artifact, ampel required three pieces:

%s
This is often an artifact such as a file. Most commonly, a policy will be evaluated
against a hash. Ampel canobtain the hashes from files for you but you can specify
them in the command line or using a subject reader.

%s
The policy code. Ampel policies are written in JSON, they can be signed and verified 
just as any other attestation. The policy contains Tenets, the principles that
we want to be true to verify an artifact. Tenets are written in a language such
as CEL and once verified are turned into Assertions once verified using available 
evidence.

%s
Evidence lets Ampel prove that the policy Tenets are true. Ampel is designed to
operate on signed attestations which capture evidence in an envelope that makes
it immutable, verifiable and linked to an identity to ensure the highest levels
of trust. Attestations can be supplied through the command line or can be obtained
using a collector.

		`,
			AmpelBanner("Amazing Multipurpose Policy Engine and L"),
			color.New(color.FgHiWhite).Sprint("The Subject"),
			color.New(color.FgHiWhite).Sprint("The Policy"),
			color.New(color.FgHiWhite).Sprint("Attested Evidence"),
		),
		Use:               "verify",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(c *cobra.Command, args []string) error {
			// Validate options
			if err := opts.Validate(); err != nil {
				return err
			}

			// Supress output from here as options are correct
			c.SilenceUsage = true

			// Generate the atestation subjects from the files
			var subjects = []attestation.Subject{}
			for _, path := range opts.SubjectFiles {
				sub, err := subject.FromPath(path)
				if err != nil {
					return fmt.Errorf("generating subject from %q: %w", path, err)
				}
				subjects = append(subjects, sub)
			}
			fmt.Printf("%+v", subjects)

			// Parse the polcy file
			parser := policy.NewParser()
			p, err := parser.ParseFile(opts.PolicyFile)
			if err != nil {
				return fmt.Errorf("parsing policy: %w", err)
			}
			// fmt.Printf("policy: %+v\n", p)

			// Run the ampel verifier
			ampel, err := verifier.New()
			if err != nil {
				return fmt.Errorf("creating verifier")
			}

			results, err := ampel.Verify(context.Background(), &opts.VerificationOptions, p, subjects[0])
			if err != nil {
				return fmt.Errorf("runnig subject verification: %w", err)
			}

			if opts.Format == "controls" {
				t := table.NewWriter()
				t.SetOutputMirror(os.Stdout)
				t.AppendHeader(table.Row{"Class", "Control", "Status"})
				rows := []table.Row{}
				for _, r := range results.Results {
					for _, c := range r.Controls {
						rows = append(rows, table.Row{c.Class, c.Id, r.Status})
					}
				}
				t.AppendRows(rows)
				t.Render()
			} else {
				fmt.Printf("Results:\n%+v\n", results)
			}

			return nil
		},
	}

	opts.AddFlags(evalCmd)
	parentCmd.AddCommand(evalCmd)
}
