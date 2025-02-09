// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/ampel/pkg/verifier"
	"github.com/spf13/cobra"
)

type statusOptions struct {
	SubjectFiles []string
	Results      []string
	CatalogPath  string
}

// AddFlags adds the flags
func (o *statusOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVarP(
		&o.SubjectFiles, "subject", "s", []string{}, "list of files to vertify",
	)

	cmd.PersistentFlags().StringSliceVarP(
		&o.Results, "result", "r", o.Results, "attested results",
	)

	cmd.PersistentFlags().StringVarP(
		&o.CatalogPath, "catalog", "c", o.CatalogPath, "path to OSCAL catalog file",
	)
}

func (o *statusOptions) Validate() error {
	var errs = []error{}
	if len(o.SubjectFiles) == 0 {
		errs = append(errs, errors.New("no subject files specified"))
	}
	return errors.Join(errs...)
}

func addStatus(parentCmd *cobra.Command) {
	opts := verifyOptions{
		VerificationOptions: verifier.NewVerificationOptions(),
		PolicyFile:          "",
		SubjectFiles:        []string{},
	}
	evalCmd := &cobra.Command{
		Short: "check artifacts against a policy",
		Long: fmt.Sprintf(`
%s

Ampel status returns the compliance status of an artifact based
on historical policy evaluations. Evaluations are matched against
an OSCAL catalog or profile.
`, AmpelBanner("Amazing Multipurpose Policy Engine and L")),
		Use:               "verify",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(c *cobra.Command, args []string) error {
			// Validate options
			if err := opts.Validate(); err != nil {
				return err
			}
			c.SilenceUsage = true
			return nil
		},
	}

	opts.AddFlags(evalCmd)
	parentCmd.AddCommand(evalCmd)
}
