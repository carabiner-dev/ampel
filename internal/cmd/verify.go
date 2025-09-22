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

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/hasher"
	"github.com/carabiner-dev/policy"
	papi "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/policy/options"
	"github.com/carabiner-dev/signer/key"
	"github.com/fatih/color"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/helpers"

	"github.com/carabiner-dev/ampel/internal/render"
	acontext "github.com/carabiner-dev/ampel/pkg/context"
	"github.com/carabiner-dev/ampel/pkg/verifier"
)

var (
	hashRegexStr = `^(\bsha1\b|\bsha256\b|\bsha512\b|\bsha3\b|\bgitCommit\b):([a-f0-9]+)$`
	hashRegex    *regexp.Regexp
)

type verifyOptions struct {
	verifier.VerificationOptions
	command.KeyOptions
	PolicyLocation        string
	Format                string
	PolicyOutput          bool
	ContextEnv            bool
	ContextJSON           string
	ContextStringVals     []string
	Collectors            []string
	Subject               string
	SubjectFile           string
	SubjectHash           string
	PolicyIdentityStrings []string
	PolicyVerify          bool
	PolicyKeyPaths        []string
}

// AddFlags adds the flags
func (o *verifyOptions) AddFlags(cmd *cobra.Command) {
	o.KeyOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVarP(
		&o.Subject, "subject", "s", "", "subject hash (algo:value) or a path to a files to verify ",
	)

	cmd.PersistentFlags().StringVar(
		&o.SubjectFile, "subject-file", "", "file to verify",
	)

	cmd.PersistentFlags().StringVar(
		&o.SubjectHash, "subject-hash", "", "hash to verify",
	)

	cmd.PersistentFlags().StringVarP(
		&o.PolicyLocation, "policy", "p", "", "policy/policySet location (can be a file URL or VCS locator)",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.AttestationFiles, "attestation", "a", o.AttestationFiles, "additional attestations to read",
	)

	cmd.PersistentFlags().BoolVar(
		&o.AttestResults, "attest-results", o.AttestResults, "write an attestation with the evaluation results to --results-path",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.ContextStringVals, "context", "x", []string{}, "evaluation context value definitions",
	)

	cmd.PersistentFlags().StringVar(
		&o.ContextJSON, "context-json", "", "JSON struct with the context definition or prefix with @ to read from a file",
	)

	cmd.PersistentFlags().BoolVar(
		&o.ContextEnv, "context-env", true, "Support reading context values from env vars",
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

	cmd.PersistentFlags().BoolVar(
		&o.SetExitCode, "exit-code", true, "set a non-zero exit code on policy verification fail",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.Policies, "pid", []string{}, "list of policy IDs to evaluate from a set (defaults to all)",
	)

	cmd.PersistentFlags().BoolVar(
		&o.PolicyOutput, "policy-out", false, "render the eval results per policy, more detailed than the set view",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.IdentityStrings, "signer", []string{}, "list of signer identities to verify attestations",
	)

	cmd.PersistentFlags().BoolVar(
		&o.EnforceExpiration, "expiration", verifier.DefaultVerificationOptions.EnforceExpiration, "enforce policy expiration dates",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.PolicyIdentityStrings, "policy-signer", []string{}, "signer identities to verify signed policies",
	)

	cmd.PersistentFlags().BoolVar(
		&o.PolicyVerify, "policy-verify", true, "verify policy signatures",
	)

	cmd.PersistentFlags().StringSliceVar(
		&o.PolicyKeyPaths, "policy-key", []string{}, "path to public keys to verify policies",
	)

	cmd.PersistentFlags().Int8Var(
		&o.ParallelWorkers, "workers", verifier.DefaultVerificationOptions.ParallelWorkers, "number of evaluation threads to run in parallel",
	)

	cmd.PersistentFlags().BoolVar(
		&o.AllowEmptySetChains, "allow-empty-set-chain", verifier.DefaultVerificationOptions.AllowEmptySetChains, "don't fail PolicySets when chains are empty",
	)
}

func parseHash(estring string) (algo, value string, err error) {
	if hashRegex == nil {
		hashRegex = regexp.MustCompile(hashRegexStr)
	}

	// If the string matches algo:hexValue then we never try to look
	// for a file. Never.
	pts := hashRegex.FindStringSubmatch(estring)
	if pts != nil {
		algo := strings.ToLower(pts[1])
		if _, ok := intoto.HashAlgorithms[algo]; !ok {
			return "", "", errors.New("invalid hash algorithm in subject")
		}
		return algo, pts[2], nil
	}
	return "", "", fmt.Errorf("error parsing hash string")
}

// SubjectDescriptor parses the subject string read from the command line
// and returns a resource descriptor, either by synhesizing it from the specified
// hash or by hashing a file.
func (o *verifyOptions) SubjectDescriptor() (attestation.Subject, error) {
	// If we have a hash, check it and create the descriptor:
	if o.SubjectHash != "" {
		algo, val, err := parseHash(o.SubjectHash)
		if err != nil {
			return nil, err
		}

		return &intoto.ResourceDescriptor{
			Digest: map[string]string{algo: val},
		}, nil
	}

	hashes, err := hasher.New().HashFiles([]string{o.SubjectFile})
	if err != nil {
		return nil, fmt.Errorf("hashing subject file: %w", err)
	}
	return hashes.ToResourceDescriptors()[0], nil
}

// LoadPublicKeys parses the public keys and loads them into the verification
// options set.
func (o *verifyOptions) LoadPublicKeys() error {
	keys, err := o.ParseKeys()
	if err != nil {
		return err
	}
	o.Keys = keys
	return nil
}

func (o *verifyOptions) Validate() error {
	errs := []error{}
	if o.SubjectFile == "" && o.SubjectHash == "" {
		errs = append(errs, fmt.Errorf("no subject specified (use --subject, --subject-file or --subject-hash)"))
	}

	if o.SubjectFile != "" && o.SubjectHash != "" {
		errs = append(errs, fmt.Errorf("subject specified twice (as file and hash)"))
	}

	if o.PolicyLocation == "" {
		errs = append(errs, errors.New("a policy file must be defined"))
	}

	if o.Format == "" {
		errs = append(errs, errors.New("no format defined"))
	} else {
		if err := render.GetDriverBytType(o.Format); err != nil {
			errs = append(errs, errors.New("invalid format"))
		}
	}

	if o.ParallelWorkers <= 0 {
		errs = append(errs, errors.New("parallel workers must be larger than 0"))
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
against a hash. AMPEL can compute the hashes from files for you (--subject-file)
or you can specify a hash in the command line using --subject-hash.

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
			if len(args) > 0 {
				if opts.Subject == "" {
					opts.Subject = args[0]
				} else if opts.Subject != args[0] {
					return fmt.Errorf("subject specified twice (as argument and flag)")
				}
			}

			if opts.Subject != "" {
				// Always check the hash first to avoid fooling the hash with a
				// carfule placed file
				if _, _, err := parseHash(opts.Subject); err == nil {
					if opts.SubjectHash == "" {
						opts.SubjectHash = opts.Subject
					} else if opts.SubjectHash != opts.Subject {
						return fmt.Errorf("subject hash specified twice")
					}
				} else if helpers.Exists(opts.Subject) {
					if opts.SubjectFile == "" {
						opts.SubjectFile = opts.Subject
					} else {
						return fmt.Errorf("subject file specified twice")
					}
				} else {
					return fmt.Errorf("unable to identify subject string %q", opts.Subject)
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

			// Parse any keys for the policy check
			keys, err := parsePolicyKeys(&opts)
			if err != nil {
				return err
			}

			// Compile the policy or location
			set, pcy, ver, err := policy.NewCompiler().CompileVerifyLocation(
				opts.PolicyLocation,
				options.WithIdentityString(opts.PolicyIdentityStrings...),
				options.WithPublicKey(keys...),
				options.WithVerifySignatures(opts.PolicyVerify),
			)
			if err != nil {
				return fmt.Errorf("compiling policy: %w", err)
			}

			if opts.PolicyVerify && ver != nil {
				if !ver.GetVerified() {
					//nolint:errcheck,forcetypeassert
					return fmt.Errorf("policy signature verification failed: %w", ver.(error))
				}
			}

			// Load the built-in repository types
			if err := collector.LoadDefaultRepositoryTypes(); err != nil {
				return fmt.Errorf("loading repository collector types: %w", err)
			}

			// Run the ampel verifier
			ampel, err := verifier.New(verifier.WithCollectorInits(opts.Collectors))
			if err != nil {
				return fmt.Errorf("creating verifier: %w", err)
			}

			if err := opts.LoadPublicKeys(); err != nil {
				return fmt.Errorf("loading keys: %w", err)
			}

			// Build the context providers as specified in the options
			if err := buildContextProviders(&opts); err != nil {
				return fmt.Errorf("building context providers: %w", err)
			}

			// Run the evaluation:
			results, err := ampel.Verify(context.Background(), &opts.VerificationOptions, policy.PolicyOrSet(set, pcy), subject)
			if err != nil {
				return fmt.Errorf("running subject verification: %w", err)
			}

			// Generate the results attestation
			if opts.AttestResults {
				attFile, err := os.Create(opts.ResultsAttestationPath)
				if err != nil {
					return fmt.Errorf("unable to open results attestation path")
				}

				if err := ampel.AttestResults(attFile, results); err != nil {
					return fmt.Errorf("writing results attestation: %w", err)
				}
			}

			eng := render.NewEngine()
			if err := eng.SetDriver(opts.Format); err != nil {
				return err
			}

			switch r := results.(type) {
			case *papi.Result:
				if err := eng.RenderResult(os.Stdout, r); err != nil {
					return fmt.Errorf("rendering result: %w", err)
				}
			case *papi.ResultSet:
				if opts.PolicyOutput || len(opts.Policies) > 0 {
					for _, r := range r.GetResults() {
						if err := eng.RenderResult(os.Stdout, r); err != nil {
							return fmt.Errorf("rendering results: %w", err)
						}
					}
				} else if err := eng.RenderResultSet(os.Stdout, r); err != nil {
					return fmt.Errorf("rendering results: %w", err)
				}
			}

			if results.GetStatus() == papi.StatusFAIL && opts.SetExitCode {
				os.Exit(1)
			}

			return nil
		},
	}

	opts.AddFlags(evalCmd)
	parentCmd.AddCommand(evalCmd)
}

func buildContextProviders(opts *verifyOptions) error {
	// Pass the -x flags as a new StringMapList list provider
	if len(opts.ContextStringVals) > 0 {
		l := acontext.StringMapList(opts.ContextStringVals)
		opts.WithContextProvider(&l)
	}

	// Read the evaluation context data from JSON:
	if opts.ContextJSON != "" {
		provider, err := acontext.NewProviderFromJSONFile(opts.ContextJSON)
		if err != nil {
			return fmt.Errorf("processing JSON context: %w", err)
		}
		opts.WithContextProvider(provider)
	}

	// Load the environment context reader if selected
	if opts.ContextEnv {
		opts.WithContextProvider(acontext.NewEnvContextReader())
	}
	return nil
}

// parsePolicyKeys parses the policy public keus
func parsePolicyKeys(opt *verifyOptions) ([]key.PublicKeyProvider, error) {
	parser := key.NewParser()
	ret := []key.PublicKeyProvider{}
	for _, path := range opt.PolicyKeyPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading policy key file: %w", err)
		}
		k, err := parser.ParsePublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		ret = append(ret, k)
	}
	return ret, nil
}
