package correlator_test

import (
	"testing"
	"time"

	"alertcorr/internal/correlator"
	"alertcorr/internal/model"
	"alertcorr/internal/store"
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

// 两个独立父事件同轮先后恢复：两条恢复通知必须各自保留（按事件身份
// 判重而非文案）；重开存储后重放同一回报仍是 duplicate，不产生多份通知；
// 子告警恢复通知关联到被抑制主体并保留当时各原因的依据。
func TestIndependentParentsResolveEachNotified(t *testing.T) {
	eng, fire := multiSetup(t)
	eng.Process(fire("d", "db/p", "db", 1))
	eng.Process(fire("n", "net/p", "net", 1))
	eng.Process(fire("a", "app/h", "app", 1, "db", "net"))
	st := eng.Store()

	resolve := func(id, fp, src string) model.Alert {
		return model.Alert{ID: id, Fingerprint: fp, Source: src, Check: "h",
			Status: model.StatusResolved, Epoch: 1, StartsAt: time.Now()}
	}
	eng.Process(resolve("dr", "db/p", "db"))
	if got := countKind(st.Notifications, "alert_resumed"); got != 0 {
		t.Fatalf("net still suppresses: want 0 resumed, got %d", got)
	}
	eng.Process(resolve("nr", "net/p", "net"))
	if got := countKind(st.Notifications, "incident_resolved"); got != 2 {
		t.Fatalf("two independent parents must each keep a resolved notification, got %d", got)
	}
	var resumed *model.Notification
	for i := range st.Notifications {
		if st.Notifications[i].Kind == "alert_resumed" {
			resumed = &st.Notifications[i]
		}
	}
	if resumed == nil || resumed.SubjectID == "" {
		t.Fatal("resumed notification must bind to the suppressed subject")
	}
	if len(resumed.Basis) != 2 {
		t.Fatalf("resumed notification must keep the basis of both causes, got %+v", resumed.Basis)
	}

	// 存储重开后重放同一批回报：全部 duplicate，通知数不变。
	st2, err := store.Open(st.Dir())
	if err != nil {
		t.Fatal(err)
	}
	eng2 := correlator.New(st2, newRec())
	n0 := len(st2.Notifications)
	for _, a := range []model.Alert{resolve("dr", "db/p", "db"), resolve("nr", "net/p", "net")} {
		r, err := eng2.Process(a)
		if err != nil || r.Outcome != correlator.OutcomeDuplicate {
			t.Fatalf("replay after reopen must be duplicate, got %v %v", r.Outcome, err)
		}
	}
	if len(st2.Notifications) != n0 {
		t.Fatalf("replay must not add notifications: %d -> %d", n0, len(st2.Notifications))
	}
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
