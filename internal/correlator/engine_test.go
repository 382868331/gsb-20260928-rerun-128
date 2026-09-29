package correlator_test

import (
	"testing"
	"time"

	"alertcorr/internal/correlator"
	"alertcorr/internal/model"
	"alertcorr/internal/notify"
	"alertcorr/internal/store"
)

func setup(t *testing.T) (*correlator.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRules(model.RuleSet{
		Version: "v1",
		Dependencies: []model.DependencyEdge{
			{Parent: "db", Child: "app"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	eng := correlator.New(st, &notify.Recording{})
	eng.SetClock(func() time.Time { return base })
	return eng, st
}

func fire(id, fp, src string, epoch int, deps ...string) model.Alert {
	return model.Alert{ID: id, Fingerprint: fp, Source: src, Check: "chk",
		Status: model.StatusFiring, Epoch: epoch, DependsOn: deps,
		StartsAt: time.Now()}
}

func TestMergeSameEpochOnly(t *testing.T) {
	eng, _ := setup(t)
	if r, _ := eng.Process(fire("1", "db/ping", "db", 1)); r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("want opened, got %s", r.Outcome)
	}
	if r, _ := eng.Process(fire("2", "db/ping", "db", 1)); r.Outcome != correlator.OutcomeMerged {
		t.Fatalf("want merged, got %s", r.Outcome)
	}
}

func TestLateRecoveryDoesNotCloseNewEpoch(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("1", "db/ping", "db", 1))
	eng.Process(model.Alert{ID: "2", Fingerprint: "db/ping", Source: "db",
		Status: model.StatusResolved, Epoch: 1, StartsAt: time.Now()})
	eng.Process(fire("3", "db/ping", "db", 2))
	r, _ := eng.Process(model.Alert{ID: "4", Fingerprint: "db/ping", Source: "db",
		Status: model.StatusResolved, Epoch: 1, StartsAt: time.Now()})
	if r.Outcome != correlator.OutcomeStaleRecovery {
		t.Fatalf("want stale_recovery, got %s", r.Outcome)
	}
	if inc := st.ActiveIncident("db/ping"); inc == nil || inc.Epoch != 2 {
		t.Fatal("epoch-2 incident must stay active after stale recovery")
	}
}

func TestSuppressionRequiresExplicitEvidence(t *testing.T) {
	eng, _ := setup(t)
	eng.Process(fire("1", "db/ping", "db", 1))
	// 无依赖证据：即使消息再像也不抑制、不合并。
	r, _ := eng.Process(model.Alert{ID: "2", Fingerprint: "app/http", Source: "app",
		Check: "http", Status: model.StatusFiring, Epoch: 1,
		Message: "db ping down", StartsAt: time.Now()})
	if r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("no evidence: want opened, got %s", r.Outcome)
	}
	// 有 DependsOn 但规则图未确认该边：仍不抑制。
	r, _ = eng.Process(fire("3", "other/x", "other", 1, "db"))
	if r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("unconfirmed edge: want opened, got %s", r.Outcome)
	}
	// 证据齐全：抑制。
	r, _ = eng.Process(fire("4", "app2/http", "app", 1, "db"))
	if r.Outcome != correlator.OutcomeSuppressed {
		t.Fatalf("with evidence: want suppressed, got %s", r.Outcome)
	}
}

func TestSuppressionSurvivesRestart(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("1", "db/ping", "db", 1))
	dir := st.Dir()
	st2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	eng2 := correlator.New(st2, &notify.Recording{})
	r, _ := eng2.Process(fire("2", "app/http", "app", 1, "db"))
	if r.Outcome != correlator.OutcomeSuppressed {
		t.Fatalf("after restart: want suppressed, got %s", r.Outcome)
	}
}
