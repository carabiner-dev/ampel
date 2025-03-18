package verifier

import (
	"context"
	"errors"
	"fmt"
	"io"

	api "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Verify checks a subject against a policy using the available evidence
func (ampel *Ampel) Verify(
	ctx context.Context, opts *VerificationOptions, policy any, subject attestation.Subject,
) (*api.ResultSet, error) {
	switch v := policy.(type) {
	case *api.Policy:
		res, err := ampel.VerifySubjectWithPolicy(ctx, opts, v, subject)
		if err != nil {
			return nil, err
		}
		return &api.ResultSet{Results: []*api.Result{res}}, nil
	case *api.PolicySet:
		var rs = &api.ResultSet{}
		for i, p := range v.Policies {
			res, err := ampel.VerifySubjectWithPolicy(ctx, opts, p, subject)
			if err != nil {
				return nil, fmt.Errorf("evaluating policy #%d: %w", i, err)
			}
			rs.Results = append(rs.Results, res)
		}
		return rs, nil
	case []*api.PolicySet:
		var rs = &api.ResultSet{}
		for j, ps := range v {
			for i, p := range ps.Policies {
				res, err := ampel.VerifySubjectWithPolicy(ctx, opts, p, subject)
				if err != nil {
					return nil, fmt.Errorf("evaluating policy #%d/%d: %w", j, i, err)
				}
				rs.Results = append(rs.Results, res)
			}
		}
		return rs, nil
	default:
		return nil, fmt.Errorf("did not get a policy or policy set")
	}
}

// VerifySubjectWithPolicy verifies a subject against a single policy
func (ampel *Ampel) VerifySubjectWithPolicy(
	ctx context.Context, opts *VerificationOptions, policy *api.Policy, subject attestation.Subject,
) (*api.Result, error) {
	// Build the required evaluators
	evaluators, err := ampel.impl.BuildEvaluators(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building evaluators: %w", err)
	}

	// Parse any extra files defined in the options
	atts, err := ampel.impl.ParseAttestations(ctx, opts.AttestationFiles)
	if err != nil {
		return nil, fmt.Errorf("parsing files: %w", err)
	}

	// Process chained subjects:
	var chain []*api.ChainedSubject
	subject, chain, err = ampel.impl.ProcessChainedSubjects(ctx, opts, evaluators, ampel.Collector, policy, subject, atts)
	if err != nil {
		return nil, fmt.Errorf("processing chained subject: %w", err)
	}

	// Fetch applicable evidence
	moreatts, err := ampel.impl.GatherAttestations(ctx, opts, ampel.Collector, policy, subject)
	if err != nil {
		return nil, fmt.Errorf("gathering evidence: %w", err)
	}
	atts = append(atts, moreatts...)

	// Here, the policy may not require attestations (noop) but it's a corner
	// case, we'll fix it later.
	if len(atts) == 0 {
		return nil, errors.New("no evidence found to evaluate policy")
	}

	// Check identities to see if the attestations can be admitted
	// TODO(puerco)
	// Option: Unmatched identities cause a:fail or b:ignore
	allow, err := ampel.impl.CheckIdentities(opts, policy.Identities, atts)
	if err != nil {
		return nil, fmt.Errorf("admission failed: %w", err)
	}

	if !allow {
		return &api.Result{
			Status:      "FAIL",
			DateStart:   timestamppb.Now(),
			DateEnd:     timestamppb.Now(),
			Policy:      &api.PolicyRef{},
			EvalResults: []*api.EvalResult{},
			Chain:       chain,
		}, nil
	}

	// Filter attestations to those applicable to the subject
	preds, err := ampel.impl.FilterAttestations(opts, subject, atts)
	if err != nil {
		return nil, fmt.Errorf("filtering attestations: %w", err)
	}

	transformers, err := ampel.impl.BuildTransformers(opts, policy)
	if err != nil {
		return nil, fmt.Errorf("building policy transformers: %w", err)
	}

	// Apply the defined tranformations to the predicates
	preds, err = ampel.impl.Transform(opts, transformers, policy, preds)
	if err != nil {
		return nil, fmt.Errorf("applying transformations: %w", err)
	}

	// Eval Policy
	result, err := ampel.impl.VerifySubject(ctx, opts, evaluators, policy, subject, preds)
	if err != nil {
		return nil, fmt.Errorf("verifying subject: %w", err)
	}

	result.Chain = chain

	// Assert the status from the evaluation results
	if err := ampel.impl.AssertResult(policy, result); err != nil {
		return nil, fmt.Errorf("asserting results: %w", err)
	}

	// Generate the results attestation. If the attestation is disabled in the
	// options, this is a NOOP.
	if err := ampel.impl.AttestResult(ctx, opts, result); err != nil {
		return nil, fmt.Errorf("attesting results: %w", err)
	}

	// Generate outputs
	return result, nil
}

// AttestResult writes an attestation capturing an evaluation result
func (ampel *Ampel) AttestResult(w io.Writer, result *api.Result) error {
	return ampel.impl.AttestResultToWriter(w, result)
}

// AttestResult writes an attestation capturing an evaluation result
func (ampel *Ampel) AttestResultSet(w io.Writer, resultset *api.ResultSet) error {
	return ampel.impl.AttestResultSetToWriter(w, resultset)
}
