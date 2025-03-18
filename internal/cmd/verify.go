// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/ampel/internal/render"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/collector"
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
	Collectors       []string
	Subject          string
}

// AddFlags adds the flags
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&o.Subject, "subject", "s", "", "a hashes (algo:value) or paths to files to add as subjects ",
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
		&o.Format, "format", "f", "tty", "output format",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.Collectors, "collector", "c", []string{}, "attestation collectors to initialize",
	)
}

// SubjectStringToDescr parses the subkect string read from the command line
// and returns a resource descriptor, either by synhesizing it from the specified
// hash or by hashing a file.
func (o *verifyOptions) SubjectStringToDescr() (attestation.Subject, error) {
	if hashRegex == nil {
		hashRegex = regexp.MustCompile(hashRegexStr)
	}

	// If the string matches algo:hexValue then we never try to look
	// for a file. Never.
	pts := hashRegex.FindStringSubmatch(o.Subject)
	if pts != nil {
		algo := strings.ToLower(pts[0])
		if _, ok := intoto.HashAlgorithms[algo]; !ok {
			return nil, errors.New("invalid hash algorithm in subject")
		}
		return &intoto.ResourceDescriptor{
			Digest: map[string]string{algo: pts[1]},
		}, nil
	}

	return subject.FromPath(o.Subject)
}

func (o *verifyOptions) Validate() error {
	var errs = []error{}
	if o.Subject == "" {
		errs = append(errs, errors.New("no subject specified"))
	}

	if o.PolicyFile == "" {
		errs = append(errs, errors.New("a polciy file must be defined"))
	}

	if o.Format == "" {
		errs = append(errs, errors.New("no format defined"))
	} else {
		if err := render.GetDriverBytType(o.Format); err != nil {
			errs = append(errs, errors.New("invalid format"))
		}
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

			if len(args) > 0 && opts.Subject != "" {
				return fmt.Errorf("subject specified twice (-s and arg)")
			}

			if len(args) > 0 {
				opts.Subject = args[0]
			}

			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			// Validate options
			if err := opts.Validate(); err != nil {
				return err
			}

			// Supress output from here as options are correct
			c.SilenceUsage = true

			// Read the subject from the specified string:
			subject, err := opts.SubjectStringToDescr()
			if err != nil {
				return fmt.Errorf("resolving subject string: %w", err)
			}

			// Parse the polcy file
			parser := policy.NewParser()
			p, err := parser.ParseFile(opts.PolicyFile)
			if err != nil {
				return fmt.Errorf("parsing policy: %w", err)
			}

			// Load the built in repository types
			if err := collector.LoadDefaultRepositoryTypes(); err != nil {
				return fmt.Errorf("loading repository collector types: %w", err)
			}
			// Run the ampel verifier
			ampel, err := verifier.New(verifier.WithCollectorInits(opts.Collectors))
			if err != nil {
				return fmt.Errorf("creating verifier: %w", err)
			}

			results, err := ampel.Verify(context.Background(), &opts.VerificationOptions, p, subject)
			if err != nil {
				return fmt.Errorf("runnig subject verification: %w", err)
			}

			eng := render.NewEngine()
			if err := eng.SetDriver(opts.Format); err != nil {
				return err
			}

			if err := eng.RenderResultSet(os.Stdout, results); err != nil {
				return fmt.Errorf("rendering results: %w", err)
			}

			return nil
		},
	}

	opts.AddFlags(evalCmd)
	parentCmd.AddCommand(evalCmd)
}
