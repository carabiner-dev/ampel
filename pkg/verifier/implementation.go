package verifier

import (
	"errors"

	"github.com/puerco/ampel/pkg/policy"
	"github.com/puerco/ampel/pkg/principal"
	"github.com/puerco/ampel/pkg/storage"
)

type defaultIplementation struct{}

func (di *defaultIplementation) GetObjectPolicies(repos []storage.Repository, obj *principal.Object) (*policy.Checklist, error) {
	if len(repos) == 0 {
		return nil, errors.New("unable to fetch checks, no repos defined")
	}

	repos = storage.FilterRepos(repos, storage.FilterPolicyStore)
	if len(repos) == 0 {
		return nil, errors.New("unable to get policies, no repositories to fetch from")
	}

	// TODO(puerco): Parallelize
	checklist := []*policy.Checklist{}
	for _, b := range repos {

	}

	return nil, nil
}
func (di *defaultIplementation) EvalObject(*policy.Checklist, *principal.Object) (*policy.ResultSet, error) {
	return nil, nil
}
