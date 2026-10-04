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

func TestDuplicateReplayIsIdempotent(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("1", "db/ping", "db", 1))
	r, _ := eng.Process(fire("1", "db/ping", "db", 1))
	if r.Outcome != correlator.OutcomeDuplicate {
		t.Fatalf("want duplicate, got %s", r.Outcome)
	}
	if len(st.Alerts) != 1 || len(st.Notifications) != 1 {
		t.Fatalf("replay must not duplicate alerts/notifications: %d alerts, %d notifications",
			len(st.Alerts), len(st.Notifications))
	}
}

func TestLateParentAbsorbsChildIncident(t *testing.T) {
	eng, st := setup(t)
	if r, _ := eng.Process(fire("1", "app/http", "app", 1, "db")); r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("child before parent: want opened, got %s", r.Outcome)
	}
	if r, _ := eng.Process(fire("2", "db/ping", "db", 1)); r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("late parent: want opened, got %s", r.Outcome)
	}
	child := st.Incidents[0]
	parent := st.Incidents[1]
	if child.Status != model.IncidentSuppressed {
		t.Fatalf("child incident must be suppressed, got %s", child.Status)
	}
	if len(parent.SuppressedAlertIDs) != 1 || parent.SuppressedAlertIDs[0] != "1" {
		t.Fatalf("parent must list absorbed alert, got %v", parent.SuppressedAlertIDs)
	}
	sup := st.FindSuppression("1")
	if sup == nil || sup.Status != model.SuppressionActive || sup.RuleVersion != "v1" {
		t.Fatalf("suppression must be active with judged rule version, got %+v", sup)
	}
}

func TestApplyRulesReleasesWithdrawnEdge(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("1", "db/ping", "db", 1))
	eng.Process(fire("2", "app/http", "app", 1, "db"))
	report, err := eng.ApplyRules(model.RuleSet{Version: "v2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report) != 1 {
		t.Fatalf("want 1 review line, got %v", report)
	}
	sup := st.FindSuppression("2")
	if sup.Status != model.SuppressionReleased || sup.RuleVersion != "v1" {
		t.Fatalf("want released with original rule version v1, got %+v", sup)
	}
}

func TestLiftAndReevaluate(t *testing.T) {
	eng, st := setup(t)
	eng.Process(fire("1", "db/ping", "db", 1))
	eng.Process(fire("2", "app/http", "app", 1, "db"))
	view := eng.ViewCauses("app/http")
	if !view.Suppressed || len(view.Confirmed) != 1 {
		t.Fatalf("want one confirmed cause, got %+v", view)
	}
	explID := view.Confirmed[0].ID
	// 预演移除：这是唯一原因，应恢复通知，但尚未真正改变状态。
	prev, err := eng.PreviewRemoveCause(explID)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.WouldResume) != 1 {
		t.Fatalf("preview must resume subject, got %+v", prev)
	}
	if st.FindSuppression("2").Status != model.SuppressionActive {
		t.Fatal("preview must not mutate state")
	}
	if _, err := eng.ConfirmRemoveCause(explID); err != nil {
		t.Fatal(err)
	}
	if st.FindSuppression("2").Status != model.SuppressionReleased {
		t.Fatal("confirmed removal: suppression must be released")
	}
	if v := eng.ViewCauses("app/http"); v.Suppressed || len(v.Withdrawn) != 1 ||
		v.Withdrawn[0].EndReason != model.EndOperatorRemoved {
		t.Fatalf("cause must be withdrawn by operator, got %+v", v)
	}
	// 重复观察（同指纹同轮）不会让被操作者移除的原因复活，也不产生新原因。
	if r, _ := eng.Process(fire("3", "app/http", "app", 1, "db")); r.Outcome != correlator.OutcomeMerged {
		t.Fatalf("repeat observation must merge, not resurrect cause: %s", r.Outcome)
	}
	if v := eng.ViewCauses("app/http"); len(v.Confirmed) != 0 || len(v.Withdrawn) != 1 {
		t.Fatalf("removed cause must stay withdrawn: %+v", v)
	}
}

// TestMultipleIndependentCauses：一个告警同时有两个独立父原因时，
// 只恢复一个父事件不应重新通知；两个都恢复才恢复通知，且只通知一次。
func TestMultipleIndependentCauses(t *testing.T) {
	eng, st := setup(t)
	eng.ApplyRules(model.RuleSet{Version: "v1", Dependencies: []model.DependencyEdge{
		{Parent: "db", Child: "app"},
		{Parent: "net", Child: "app"},
	}})
	eng.Process(fire("d1", "db/ping", "db", 1))
	eng.Process(fire("n1", "net/ping", "net", 1))
	r, _ := eng.Process(model.Alert{ID: "a1", Fingerprint: "app/http", Source: "app",
		Check: "http", Status: model.StatusFiring, Epoch: 1, DependsOn: []string{"db", "net"},
		StartsAt: time.Now()})
	if r.Outcome != correlator.OutcomeSuppressed {
		t.Fatalf("want suppressed by two causes, got %s", r.Outcome)
	}
	v := eng.ViewCauses("app/http")
	if len(v.Confirmed) != 2 || len(v.AffectsNow) != 2 {
		t.Fatalf("want 2 confirmed causes, got %+v", v)
	}
	notif := len(st.Notifications)
	// 第一个原因恢复：仍有另一条 confirmed，不重新通知。
	eng.Process(model.Alert{ID: "d2", Fingerprint: "db/ping", Source: "db",
		Status: model.StatusResolved, Epoch: 1, StartsAt: time.Now()})
	if v2 := eng.ViewCauses("app/http"); !v2.Suppressed || len(v2.Confirmed) != 1 {
		t.Fatalf("one cause left: must stay suppressed, got %+v", v2)
	}
	resumed := countKind(st.Notifications[notif:], "alert_resumed")
	if resumed != 0 {
		t.Fatalf("single parent recovery must not resume, got %d", resumed)
	}
	// 第二个原因恢复：最后一条消失，恢复通知恰好一次。
	eng.Process(model.Alert{ID: "n2", Fingerprint: "net/ping", Source: "net",
		Status: model.StatusResolved, Epoch: 1, StartsAt: time.Now()})
	if countKind(st.Notifications[notif:], "alert_resumed") != 1 {
		t.Fatalf("last cause cleared: exactly one resume, got %d", countKind(st.Notifications[notif:], "alert_resumed"))
	}
	// 幂等：重算/重复观察不会再发恢复通知。
	before := len(st.Notifications)
	eng.Process(model.Alert{ID: "a1x", Fingerprint: "app/http", Source: "app",
		Check: "http", Status: model.StatusFiring, Epoch: 1, DependsOn: []string{"db", "net"},
		StartsAt: time.Now()})
	if len(st.Notifications) != before {
		t.Fatal("no duplicate resume after last cause")
	}
}

// TestSuspectedCauseDoesNotBlock：待核实原因不能压掉独立告警的通知。
func TestSuspectedCauseDoesNotBlock(t *testing.T) {
	eng, _ := setup(t) // 边 db->app 存在
	eng.Process(fire("d1", "db/ping", "db", 1))
	// 子告警未声明依赖：只产生 suspected 解释，事件仍应开立通知。
	r, _ := eng.Process(fire("a1", "app/http", "app", 1))
	if r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("suspected cause must not block: %s", r.Outcome)
	}
	v := eng.ViewCauses("app/http")
	if len(v.Suspected) != 1 || v.Suppressed {
		t.Fatalf("want one suspected, not suppressed: %+v", v)
	}
	// 无新证据的重复观察：只合并，仍只有一条待核实解释。
	r1b, _ := eng.Process(fire("a1b", "app/http", "app", 1))
	if r1b.Outcome != correlator.OutcomeMerged {
		t.Fatalf("plain repeat observation must merge: %s", r1b.Outcome)
	}
	v1b := eng.ViewCauses("app/http")
	if len(v1b.Suspected) != 1 {
		t.Fatalf("plain repeat must not add causes: %+v", v1b)
	}
	// 后补显式证据：升级为 confirmed，告警转为抑制，且不产生重复解释。
	r2, _ := eng.Process(fire("a2", "app/http", "app", 1, "db"))
	if r2.Outcome != correlator.OutcomeSuppressed {
		t.Fatalf("evidence arriving later must suppress: %s", r2.Outcome)
	}
	v2 := eng.ViewCauses("app/http")
	if len(v2.Confirmed) != 1 || len(v2.Suspected) != 0 || len(v2.Withdrawn) != 0 {
		t.Fatalf("suspected must upgrade to single confirmed: %+v", v2)
	}
}

func countKind(ns []model.Notification, kind string) int {
	n := 0
	for _, x := range ns {
		if x.Kind == kind {
			n++
		}
	}
	return n
}
