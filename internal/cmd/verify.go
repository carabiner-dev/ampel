// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/fatih/color"
	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/util"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/policy"
	"github.com/carabiner-dev/ampel/pkg/subject"
	"github.com/carabiner-dev/ampel/pkg/verifier"
)

var (
	hashRegexStr = `^(\bsha1\b|\bsha256\b|\bsha512\b|\bsha3\b|\bgitCommit\b):([a-f0-9]+)$`
	hashRegex    *regexp.Regexp
)

type verifyOptions struct {
	verifier.VerificationOptions
	PolicyFile       string
	Format           string
	SubjectAlgorithm string
	SubjectHashes    []string
	SubjectPaths     []string
	SubjectValues    []string
}

// AddFlags adds the flags
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVarP(
		&o.SubjectValues, "subject", "s", []string{}, "list of hashes (algo:value) or paths to files to add as subjects ",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.SubjectHashes, "hash-value", []string{}, "algorithm used to hash the subjects",
	)

	cmd.PersistentFlags().StringVar(
		&o.SubjectAlgorithm, "hash-algo", "sha256", "algorithm used to hash the subjects",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.SubjectPaths, "subject-file", []string{}, "path to files to use as subjects",
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

func (o *verifyOptions) SubjectValuesToDigests() []map[string]string {
	if hashRegex == nil {
		hashRegex = regexp.MustCompile(hashRegexStr)
	}
	ret := []map[string]string{}
	for _, v := range o.SubjectValues {
		pts := hashRegex.FindStringSubmatch(v)
		if pts == nil {
			continue
		}
		ret = append(ret, map[string]string{
			pts[1]: pts[2],
		})
	}
	return ret
}

func (o *verifyOptions) Validate() error {
	var errs = []error{}
	if len(o.SubjectHashes) == 0 && len(o.SubjectPaths) == 0 && len(o.SubjectValuesToDigests()) == 0 {
		errs = append(errs, errors.New("no subjects specified"))
	}

	if o.PolicyFile == "" {
		errs = append(errs, errors.New("a polciy file must be defined"))
	}
	return errors.Join(errs...)
}

func addVerify(parentCmd *cobra.Command) {
	opts := verifyOptions{
		VerificationOptions: verifier.NewVerificationOptions(),
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
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if hashRegex == nil {
				hashRegex = regexp.MustCompile(hashRegexStr)
			}
			// Transfer the files to the paths array
			vals := []string{}
			for _, v := range opts.SubjectValues {
				if util.Exists(v) {
					opts.SubjectPaths = append(opts.SubjectPaths, v)
					continue
				}
				res := hashRegex.FindStringSubmatch(v)
				if res == nil {
					return fmt.Errorf("invalid subject: %q", v)
				}
				vals = append(vals, v)
			}

			opts.SubjectValues = vals
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			// Validate options
			if err := opts.Validate(); err != nil {
				return err
			}

			// Supress output from here as options are correct
			c.SilenceUsage = true

			// Generate the atestation subjects from the files
			var subjects = []attestation.Subject{}
			for _, path := range opts.SubjectPaths {
				sub, err := subject.FromPath(path)
				if err != nil {
					return fmt.Errorf("generating subject from %q: %w", path, err)
				}
				subjects = append(subjects, sub)
			}

			for _, h := range opts.SubjectValuesToDigests() {
				subjects = append(subjects, &v1.ResourceDescriptor{
					Digest: h,
				})

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
