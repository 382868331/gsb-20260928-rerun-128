package correlator_test

import (
	"testing"
	"time"

	"alertcorr/internal/correlator"
	"alertcorr/internal/model"
)

func multiSetup(t *testing.T) (*correlator.Engine, func(string, string, string, int, ...string) model.Alert) {
	t.Helper()
	st, err := openStoreRules(t, []model.DependencyEdge{
		{Parent: "db", Child: "app"},
		{Parent: "net", Child: "app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng := correlator.New(st, newRec())
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	eng.SetClock(func() time.Time { return base })
	fire := func(id, fp, src string, epoch int, deps ...string) model.Alert {
		return model.Alert{ID: id, Fingerprint: fp, Source: src, Check: "h",
			Status: model.StatusFiring, Epoch: epoch, DependsOn: deps, StartsAt: base}
	}
	return eng, fire
}

// 移除两个原因中的一个：主体仍应被抑制，预演不得改动状态。
func TestPreviewRemoveOneOfTwoCausesKeepsSuppressed(t *testing.T) {
	eng, fire := multiSetup(t)
	eng.Process(fire("d", "db/p", "db", 1))
	eng.Process(fire("n", "net/p", "net", 1))
	eng.Process(fire("a", "app/h", "app", 1, "db", "net"))
	v := eng.ViewCauses("app/h")
	if len(v.Confirmed) != 2 {
		t.Fatalf("want 2 causes, got %d", len(v.Confirmed))
	}
	prev, err := eng.PreviewRemoveCause(v.Confirmed[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.StaySuppressed) != 1 || len(prev.WouldResume) != 0 || len(prev.OtherCauses) != 1 {
		t.Fatalf("removing one of two must keep suppressed: %+v", prev)
	}
	if got := eng.ViewCauses("app/h"); len(got.Confirmed) != 2 {
		t.Fatal("preview must not mutate state")
	}
	if _, err := eng.ConfirmRemoveCause(v.Confirmed[0].ID); err != nil {
		t.Fatal(err)
	}
	got := eng.ViewCauses("app/h")
	if !got.Suppressed || len(got.Confirmed) != 1 || len(got.Withdrawn) != 1 {
		t.Fatalf("after removing one, other cause must hold: %+v", got)
	}
}

// 关联范围收窄写入历史且不改变解释状态。
func TestNarrowScopeRecordedInHistory(t *testing.T) {
	eng, fire := multiSetup(t)
	eng.Process(fire("d", "db/p", "db", 1))
	eng.Process(fire("a", "app/h", "app", 1, "db"))
	x := eng.ViewCauses("app/h").Confirmed[0]
	if err := eng.NarrowScope(x.ID, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	after := eng.ViewCauses("app/h").Confirmed[0]
	if len(after.Scope) != 1 || after.Scope[0] != "a" || after.State != model.ExplConfirmed {
		t.Fatalf("scope narrowing failed: %+v", after)
	}
	found := false
	for _, h := range after.History {
		if h.Reason == "scope_narrowed" {
			found = true
		}
	}
	if !found {
		t.Fatal("scope narrowing must be traceable in history")
	}
}

// 旧决定的回报（迟到恢复）不能覆盖新解释。
func TestStaleRecoveryDoesNotTouchNewCause(t *testing.T) {
	eng, fire := multiSetup(t)
	eng.Process(fire("d1", "db/p", "db", 1))
	eng.Process(model.Alert{ID: "dr", Fingerprint: "db/p", Source: "db",
		Status: model.StatusResolved, Epoch: 1, StartsAt: time.Now()})
	eng.Process(fire("d2", "db/p", "db", 2))
	r, _ := eng.Process(model.Alert{ID: "dr-old", Fingerprint: "db/p", Source: "db",
		Status: model.StatusResolved, Epoch: 1, StartsAt: time.Now()})
	if r.Outcome != correlator.OutcomeStaleRecovery {
		t.Fatalf("want stale, got %s", r.Outcome)
	}
	eng.Process(fire("a", "app/h", "app", 2, "db"))
	v := eng.ViewCauses("app/h")
	if !v.Suppressed || len(v.Confirmed) != 1 {
		t.Fatalf("new epoch cause must remain intact after stale recovery: %+v", v)
	}
}
