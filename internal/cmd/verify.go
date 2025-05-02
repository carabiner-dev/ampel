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

	"github.com/carabiner-dev/hasher"
	"github.com/fatih/color"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/util"

	"github.com/carabiner-dev/ampel/internal/render"
	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/collector"
	"github.com/carabiner-dev/ampel/pkg/policy"
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
	PolicyOutput     bool
	SubjectAlgorithm string
	Collectors       []string
	Subject          string
	SubjectFile      string
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

	cmd.PersistentFlags().StringVar(
		&o.SubjectFile, "subject-file", "", "file to verify",
	)

	cmd.PersistentFlags().BoolVar(
		&o.SetExitCode, "exit-code", true, "set a non-zero exit code on policy verification fail",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.Policies, "pid", []string{}, "list of policy IDs to evaluate from a set (defaults to all)",
	)

	cmd.PersistentFlags().BoolVar(
		&o.PolicyOutput, "policy-out", false, "render the eval results per policy, more detailed than the set view",
	)
}

// SubjectDescriptor parses the subkect string read from the command line
// and returns a resource descriptor, either by synhesizing it from the specified
// hash or by hashing a file.
func (o *verifyOptions) SubjectDescriptor() (attestation.Subject, error) {
	if o.Subject == "" && o.SubjectFile == "" {
		return nil, fmt.Errorf("no subject hash or subject file defined")
	}
	// If we have a hash, check it and create the descriptor:
	if o.Subject != "" {
		if hashRegex == nil {
			hashRegex = regexp.MustCompile(hashRegexStr)
		}

		// If the string matches algo:hexValue then we never try to look
		// for a file. Never.
		pts := hashRegex.FindStringSubmatch(o.Subject)
		if pts == nil {
			return nil, fmt.Errorf("unable to parse string as hash")
		}
		algo := strings.ToLower(pts[1])
		if _, ok := intoto.HashAlgorithms[algo]; !ok {
			return nil, errors.New("invalid hash algorithm in subject")
		}
		return &intoto.ResourceDescriptor{
			Digest: map[string]string{algo: pts[2]},
		}, nil
	}

	hashes, err := hasher.New().HashFiles([]string{o.SubjectFile})
	if err != nil {
		return nil, fmt.Errorf("hashing subject file: %w", err)
	}
	return hashes.ToResourceDescriptors()[0], nil
}

func (o *verifyOptions) Validate() error {
	errs := []error{}
	if o.Subject == "" && o.SubjectFile == "" {
		errs = append(errs, errors.New("no subject or subject-file specified"))
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

	if o.Subject != "" && o.SubjectFile != "" {
		errs = append(errs, fmt.Errorf("you can only specify subject or subject file"))
	}

	if len(o.AttestationFiles) == 0 && len(o.Collectors) == 0 {
		errs = append(errs, errors.New("no attestation sources specified (collectors or files)"))
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

			if len(args) > 0 {
				// If arg 0 is a file, use it as the subject file
				if util.Exists(args[0]) {
					if opts.SubjectFile != "" {
						return fmt.Errorf("subject file specified twice (as arg and --subject-file)")
					} else {
						opts.SubjectFile = args[0]
					}
				} else {
					// .. otherwize this must be a hash or err
					if !hashRegex.MatchString(args[0]) {
						return fmt.Errorf("invalid argument, it must be a hash or a file")
					}
					if opts.Subject != "" {
						return fmt.Errorf("subject hash specified twice (-s and arg)")
					} else {
						opts.Subject = args[0]
					}
				}
			}

			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			// Validate options
			if err := opts.Validate(); err != nil {
				return err
			}

			// Suppress output from here as options are correct
			c.SilenceUsage = true

			// Read the subject from the specified string:
			subject, err := opts.SubjectDescriptor()
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
				return fmt.Errorf("running subject verification: %w", err)
			}

			eng := render.NewEngine()
			if err := eng.SetDriver(opts.Format); err != nil {
				return err
			}

			if opts.PolicyOutput || len(opts.Policies) > 0 {
				for _, r := range results.GetResults() {
					if err := eng.RenderResult(os.Stdout, r); err != nil {
						return fmt.Errorf("rendering results: %w", err)
					}
				}
			} else {
				if err := eng.RenderResultSet(os.Stdout, results); err != nil {
					return fmt.Errorf("rendering results: %w", err)
				}
			}

			if results.Status == api.StatusFAIL && opts.SetExitCode {
				os.Exit(1)
			}

			return nil
		},
	}

	opts.AddFlags(evalCmd)
	parentCmd.AddCommand(evalCmd)
}
