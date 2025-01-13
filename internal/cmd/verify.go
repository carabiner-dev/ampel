package cmd

import (
	"errors"
	"fmt"

	v1 "github.com/puerco/ampel/pkg/api/v1"
	"github.com/puerco/ampel/pkg/attestation"
	"github.com/puerco/ampel/pkg/policy"
	"github.com/puerco/ampel/pkg/subject"
	"github.com/spf13/cobra"
)

type verifyOptions struct {
	PolicyFile       string
	SubjectFiles     []string
	AttestationFiles []string
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
		&o.SubjectFiles, "attestation", "a", []string{}, "additional attestations to read",
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
	opts := verifyOptions{}
	evalCmd := &cobra.Command{
		Short:             "check artifacts against a policy",
		Long:              "checks artifacts against a policy",
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

			_ = v1.Context{
				Values: []*v1.Context_ValueDef{
					{
						Name:     "test",
						Type:     "type",
						Required: true,
					},
					// {
					// 	Name:     "test",
					// 	Type:     "type",
					// 	Required: true,
					// 	Default: &v1.Context_ValueDef_Int{
					// 		Int: 23,
					// 	},
					// },
				},
			}

			// data, err := protojson.Marshal(&ctx)
			// if err != nil {
			// 	return err
			// }
			// fmt.Printf("Policy:\n" + string(data) + "\n")

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
			policy, err := parser.ParseFile(opts.PolicyFile)
			if err != nil {
				return fmt.Errorf("parsing policy: %w", err)
			}
			fmt.Printf("policy: %+v", policy)

			return nil
		},
	}

	opts.AddFlags(evalCmd)
	parentCmd.AddCommand(evalCmd)
}
