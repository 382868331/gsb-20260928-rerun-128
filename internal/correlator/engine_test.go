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
	ev, err := eng.LiftSuppression("2")
	if err != nil {
		t.Fatal(err)
	}
	if !ev.ParentActive || !ev.EdgeConfirmed || ev.JudgedRuleVersion != "v1" {
		t.Fatalf("bad evidence: %+v", ev)
	}
	if st.FindSuppression("2").Status != model.SuppressionLifted {
		t.Fatal("suppression must be lifted")
	}
	if _, err := eng.LiftSuppression("2"); err == nil {
		t.Fatal("double lift must fail")
	}
	if _, err := eng.Reevaluate(); err != nil {
		t.Fatal(err)
	}
	if st.FindSuppression("2").Status != model.SuppressionActive {
		t.Fatal("evidence still valid: suppression must be reinstated")
	}
	// 边撤回后复判应正式解除。
	eng.LiftSuppression("2")
	eng.ApplyRules(model.RuleSet{Version: "v2"})
	if st.FindSuppression("2").Status != model.SuppressionReleased {
		t.Fatal("edge withdrawn: suppression must be released")
	}
}

// setupMulti 两个独立父源 db、cache 都影响 app。
func setupMulti(t *testing.T) (*correlator.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRules(model.RuleSet{
		Version: "v1",
		Dependencies: []model.DependencyEdge{
			{Parent: "db", Child: "app"},
			{Parent: "cache", Child: "app"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	eng := correlator.New(st, &notify.Recording{})
	eng.SetClock(func() time.Time { return base })
	return eng, st
}

func resolve(id, src string, epoch int) model.Alert {
	return model.Alert{ID: id, Fingerprint: src + "/chk", Source: src, Check: "chk",
		Status: model.StatusResolved, Epoch: epoch, StartsAt: time.Now()}
}

func TestMultiCauseNoRenotifyUntilAllRecover(t *testing.T) {
	eng, st := setupMulti(t)
	eng.Process(fire("p1", "db/chk", "db", 1))
	eng.Process(fire("p2", "cache/chk", "cache", 1))
	r, _ := eng.Process(fire("w1", "app/chk", "app", 1, "db", "cache"))
	if r.Outcome != correlator.OutcomeSuppressed {
		t.Fatalf("want suppressed, got %s", r.Outcome)
	}
	if len(st.SuppressionsFor("w1")) != 2 {
		t.Fatalf("alert must be covered by 2 independent causes, got %d", len(st.SuppressionsFor("w1")))
	}
	// 第一个原因恢复：仍有 cache 覆盖，不得重新通知。
	notifBefore := len(st.Notifications)
	eng.Process(resolve("r1", "db", 1))
	if len(st.Notifications) != notifBefore+1 { // 仅 incident_resolved
		t.Fatalf("single cause recovery must not re-notify, notifications %d -> %d",
			notifBefore, len(st.Notifications))
	}
	if len(st.SuppressionsFor("w1")) != 1 {
		t.Fatal("one suppression must remain")
	}
	if x := st.CurrentExplanation("w1"); x.Decision != "suppressed" {
		t.Fatalf("explanation must stay suppressed, got %s", x.Decision)
	}
	// 第二个原因也恢复：才改变通知决定。
	eng.Process(resolve("r2", "cache", 1))
	found := false
	for _, n := range st.Notifications {
		if n.Kind == "alert_released" {
			found = true
		}
	}
	if !found {
		t.Fatal("all causes recovered: alert_released notification expected")
	}
	if x := st.CurrentExplanation("w1"); x.Decision != "released" {
		t.Fatalf("explanation must be released, got %s", x.Decision)
	}
}

func TestPreviewRemoveCauseIsDryRun(t *testing.T) {
	eng, st := setupMulti(t)
	eng.Process(fire("p1", "db/chk", "db", 1))
	eng.Process(fire("p2", "cache/chk", "cache", 1))
	eng.Process(fire("w1", "app/chk", "app", 1, "db", "cache"))
	causeDB := st.FindCauseByIncident("inc-db/chk-1").ID

	notifBefore := len(st.Notifications)
	preview, err := eng.PreviewRemoveCause(causeDB)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.WouldRelease) != 0 || len(preview.WouldKeep) != 1 || preview.WouldKeep[0] != "w1" {
		t.Fatalf("bad preview: %+v", preview)
	}
	if len(st.Notifications) != notifBefore || len(st.SuppressionsFor("w1")) != 2 {
		t.Fatal("preview must not change any state")
	}
	// 确认移除两个原因后才重新通知。
	if _, err := eng.RemoveCause(causeDB); err != nil {
		t.Fatal(err)
	}
	if len(st.Notifications) != notifBefore {
		t.Fatal("cache still covers: removal must not re-notify")
	}
	causeCache := st.FindCauseByIncident("inc-cache/chk-1").ID
	p2, _ := eng.PreviewRemoveCause(causeCache)
	if len(p2.WouldRelease) != 1 || p2.WouldRelease[0] != "w1" {
		t.Fatalf("last cause preview must release w1: %+v", p2)
	}
	if _, err := eng.RemoveCause(causeCache); err != nil {
		t.Fatal(err)
	}
	if len(st.SuppressionsFor("w1")) != 0 {
		t.Fatal("all suppressions must be released")
	}
}

func TestPendingCauseNeverSuppresses(t *testing.T) {
	eng, st := setupMulti(t)
	c, created, err := eng.ReportCause("rumor", "疑似原因", "db")
	if err != nil || !created || c.Status != model.CausePending {
		t.Fatalf("bad report: %+v created=%v err=%v", c, created, err)
	}
	if _, created, _ := eng.ReportCause("rumor", "疑似原因", "db"); created {
		t.Fatal("duplicate report must not add a spurious cause")
	}
	// 即使有同名父源的可疑原因，没有已确认原因覆盖时仍及时通知。
	r, _ := eng.Process(fire("w1", "app/chk", "app", 1))
	if r.Outcome != correlator.OutcomeOpened {
		t.Fatalf("pending cause must not suppress, got %s", r.Outcome)
	}
	if err := eng.ConfirmCause("rumor"); err != nil {
		t.Fatal(err)
	}
	if st.FindCause("rumor").Status != model.CauseConfirmed {
		t.Fatal("cause must be confirmed")
	}
}

func TestStaleDecisionReportRejected(t *testing.T) {
	eng, st := setupMulti(t)
	eng.Process(fire("w1", "app/chk", "app", 1))
	cur := st.CurrentExplanation("w1")
	applied, err := eng.SubmitDecisionReport("w1", cur.Seq, "suppressed", "旧依据")
	if err != nil || applied {
		t.Fatalf("stale report must be rejected: applied=%v err=%v", applied, err)
	}
	if got := st.CurrentExplanation("w1"); got.Seq != cur.Seq || got.Decision != cur.Decision {
		t.Fatal("stale report must not overwrite current explanation")
	}
	applied, err = eng.SubmitDecisionReport("w1", cur.Seq+1, "notify", "新核实")
	if err != nil || !applied {
		t.Fatalf("newer report must apply: applied=%v err=%v", applied, err)
	}
}

func TestCauseViewAndRestart(t *testing.T) {
	eng, st := setupMulti(t)
	eng.Process(fire("p1", "db/chk", "db", 1))
	eng.Process(fire("w1", "app/chk", "app", 1, "db"))
	views := eng.CauseViews()
	if len(views) != 1 || len(views[0].AffectedAlertIDs) != 1 {
		t.Fatalf("bad cause views: %+v", views)
	}
	st2, err := store.Open(st.Dir())
	if err != nil {
		t.Fatal(err)
	}
	eng2 := correlator.New(st2, &notify.Recording{})
	views = eng2.CauseViews()
	if len(views) != 1 || views[0].Cause.Status != model.CauseConfirmed ||
		views[0].AffectedAlertIDs[0] != "w1" || len(views[0].Cause.History) == 0 {
		t.Fatalf("cause state must survive restart: %+v", views)
	}
	// 重复观察不增加虚假原因。
	r, _ := eng2.Process(fire("p1", "db/chk", "db", 1))
	if r.Outcome != correlator.OutcomeDuplicate || len(st2.Causes) != 1 {
		t.Fatalf("replay must not add causes: %s, %d", r.Outcome, len(st2.Causes))
	}
}
