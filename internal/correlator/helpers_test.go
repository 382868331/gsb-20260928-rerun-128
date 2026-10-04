package correlator_test

import (
	"testing"

	"alertcorr/internal/model"
	"alertcorr/internal/notify"
	"alertcorr/internal/store"
)

func openStoreRules(t *testing.T, edges []model.DependencyEdge) (*store.Store, error) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		return nil, err
	}
	if err := st.SaveRules(model.RuleSet{Version: "v1", Dependencies: edges}); err != nil {
		return nil, err
	}
	return st, nil
}

func newRec() *notify.Recording { return &notify.Recording{} }
