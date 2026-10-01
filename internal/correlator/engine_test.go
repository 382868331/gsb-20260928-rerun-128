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

func resolve(id, fp, src string, epoch int) model.Alert {
	return model.Alert{ID: id, Fingerprint: fp, Source: src,
		Status: model.StatusResolved, Epoch: epoch, StartsAt: time.Now()}
}

func TestReplayHasNoSideEffects(t *testing.T) {
	eng, st := setup(t)
	rec := &notify.Recording{}
	eng = correlator.New(st, rec)
	a := fire("1", "db/ping", "db", 1)
	if r, _ := eng.Process(a); r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("want opened, got %s", r.Outcome)
	}
	r, _ := eng.Process(a)
	if r.Outcome != correlator.OutcomeReplayed {
		t.Fatalf("want replayed, got %s", r.Outcome)
	}
	if len(st.Alerts) != 1 || len(rec.Events) != 1 {
		t.Fatalf("replay must not duplicate alerts/notifications: alerts=%d events=%d",
			len(st.Alerts), len(rec.Events))
	}
}

func TestLateParentAdoptsChildIncident(t *testing.T) {
	eng, st := setup(t)
	// 父告警迟到：子告警先独立成事件。
	if r, _ := eng.Process(fire("c1", "app/http", "app", 1, "db")); r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("want opened, got %s", r.Outcome)
	}
	if r, _ := eng.Process(fire("p1", "db/ping", "db", 1)); r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("want opened, got %s", r.Outcome)
	}
	sup := st.FindSuppression("c1")
	if sup == nil || sup.Status != model.SuppressionActive || sup.RuleVersion != "v1" {
		t.Fatalf("late parent must suppress c1 with rule version recorded: %+v", sup)
	}
	if inc := st.ActiveIncident("app/http"); inc != nil {
		t.Fatal("child incident must be closed after adoption")
	}
}

func TestReviewRulesReleasesOrphanedSuppression(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("p1", "db/ping", "db", 1))
	eng.Process(fire("c1", "app/http", "app", 1, "db"))
	if err := eng.ReviewRules(model.RuleSet{Version: "v2"}); err != nil {
		t.Fatal(err)
	}
	sup := st.FindSuppression("c1")
	if sup.Status != model.SuppressionReleased {
		t.Fatalf("want released, got %s", sup.Status)
	}
	if sup.RuleVersion != "v1" {
		t.Fatalf("original rule version must be kept, got %s", sup.RuleVersion)
	}
	if st.ActiveIncident("app/http") == nil {
		t.Fatal("released child alert must become an active incident")
	}
	if len(st.Reviews) == 0 {
		t.Fatal("review audit entries must be recorded")
	}
}

func TestReviewRulesKeepsConfirmedSuppression(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("p1", "db/ping", "db", 1))
	eng.Process(fire("c1", "app/http", "app", 1, "db"))
	err := eng.ReviewRules(model.RuleSet{Version: "v2",
		Dependencies: []model.DependencyEdge{{Parent: "db", Child: "app"}}})
	if err != nil {
		t.Fatal(err)
	}
	if sup := st.FindSuppression("c1"); sup.Status != model.SuppressionActive {
		t.Fatalf("confirmed edge: suppression must stay active, got %s", sup.Status)
	}
}

func TestLiftAndRejudge(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("p1", "db/ping", "db", 1))
	eng.Process(fire("c1", "app/http", "app", 1, "db"))
	ev, err := eng.LiftSuppression("c1")
	if err != nil {
		t.Fatal(err)
	}
	if !ev.EdgeConfirmed || ev.RuleVersion != "v1" || ev.Parent == nil || ev.Parent.Source != "db" {
		t.Fatalf("bad evidence: %+v", ev)
	}
	if st.ActiveIncident("app/http") == nil {
		t.Fatal("lifted alert must become visible as active incident")
	}
	// 父事件仍活动且边仍确认：重判恢复抑制。
	if err := eng.RejudgeSuppression("c1"); err != nil {
		t.Fatal(err)
	}
	if sup := st.FindSuppression("c1"); sup.Status != model.SuppressionActive {
		t.Fatalf("want reinstated, got %s", sup.Status)
	}
	// 再次解除后父事件恢复：重判应正式解除。
	if _, err := eng.LiftSuppression("c1"); err != nil {
		t.Fatal(err)
	}
	eng.Process(resolve("p2", "db/ping", "db", 1))
	if err := eng.RejudgeSuppression("c1"); err != nil {
		t.Fatal(err)
	}
	if sup := st.FindSuppression("c1"); sup.Status != model.SuppressionReleased {
		t.Fatalf("parent resolved: want released, got %s", sup.Status)
	}
}

func TestStaleRecoveryNotNotifiedOnNewEpoch(t *testing.T) {
	eng, st := setup(t)
	rec := &notify.Recording{}
	eng = correlator.New(st, rec)
	eng.Process(fire("1", "db/ping", "db", 1))
	eng.Process(resolve("2", "db/ping", "db", 1))
	eng.Process(fire("3", "db/ping", "db", 2))
	before := len(rec.Events)
	r, _ := eng.Process(resolve("4", "db/ping", "db", 1))
	if r.Outcome != correlator.OutcomeStaleRecovery {
		t.Fatalf("want stale_recovery, got %s", r.Outcome)
	}
	if len(rec.Events) != before {
		t.Fatal("stale recovery must not emit notifications on the new epoch incident")
	}
}
