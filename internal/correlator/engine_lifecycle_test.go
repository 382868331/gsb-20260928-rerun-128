package correlator_test

import (
	"testing"
	"time"

	"alertcorr/internal/correlator"
	"alertcorr/internal/model"
	"alertcorr/internal/store"
)

// lifecycleAlerts 构造 db/net 两个独立父事件与 app 子告警（多原因）。
func lifecycleSetup(t *testing.T) (*correlator.Engine, *store.Store) {
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
	return eng, st
}

func lcFire(id, src string, epoch int, deps ...string) model.Alert {
	return model.Alert{ID: id, Fingerprint: src + "/h", Source: src, Check: "h",
		Status: model.StatusFiring, Epoch: epoch, DependsOn: deps, StartsAt: time.Now()}
}

func lcResolve(id, src string, epoch int) model.Alert {
	return model.Alert{ID: id, Fingerprint: src + "/h", Source: src, Check: "h",
		Status: model.StatusResolved, Epoch: epoch, StartsAt: time.Now()}
}

func notifsWithSubject(ns []model.Notification, subject string) []model.Notification {
	var out []model.Notification
	for i := range ns {
		if ns[i].SubjectID == subject {
			out = append(out, ns[i])
		}
	}
	return out
}

func notifByKind(ns []model.Notification, kind string) *model.Notification {
	for i := range ns {
		if ns[i].Kind == kind {
			return &ns[i]
		}
	}
	return nil
}

// TestLifecycleSubjectIdentityUnified：同一子事件的抑制通知、每条原因撤回通知与
// 恢复通知必须使用同一个 subject_id（子事件 ID）；原告警 ID 与指纹作为可查询的
// 关联字段保留；不依赖通知文本串联。
func TestLifecycleSubjectIdentityUnified(t *testing.T) {
	eng, st := lifecycleSetup(t)
	eng.Process(lcFire("d", "db", 1))
	eng.Process(lcFire("n", "net", 1))
	eng.Process(lcFire("a", "app", 1, "db", "net"))

	child := st.LatestIncident("app/h")
	if child == nil {
		t.Fatal("child incident missing")
	}
	subject := child.ID

	suppressed := notifByKind(st.Notifications, "alert_suppressed")
	if suppressed == nil {
		t.Fatal("alert_suppressed notification missing")
	}
	if suppressed.SubjectID != subject {
		t.Fatalf("suppressed subject %q, want child incident %q", suppressed.SubjectID, subject)
	}
	if suppressed.AlertID != "a" || suppressed.Fingerprint != "app/h" {
		t.Fatalf("suppressed must keep alert id/fingerprint as links, got %+v", suppressed)
	}
	if len(suppressed.Basis) != 2 {
		t.Fatalf("suppressed basis must snapshot both causes, got %+v", suppressed.Basis)
	}

	// 第一条原因（db）消失：该父事件的恢复/撤回通知保留，但子告警不恢复通知。
	eng.Process(lcResolve("dr", "db", 1))
	withdrawn := notifByKind(st.Notifications, "explanation_withdrawn")
	if withdrawn == nil {
		t.Fatal("explanation_withdrawn notification missing")
	}
	if withdrawn.SubjectID != subject {
		t.Fatalf("withdrawn subject %q, want %q", withdrawn.SubjectID, subject)
	}
	if withdrawn.Fingerprint != "app/h" {
		t.Fatalf("withdrawn must keep fingerprint as link, got %+v", withdrawn)
	}
	if notifByKind(st.Notifications, "alert_resumed") != nil {
		t.Fatal("one cause remains: must not resume yet")
	}

	// 最后一条原因（net）消失：恰好一条恢复通知，主体仍是同一子事件，
	// 且依据快照能追到当时的每一个原因（含其解释 ID、父事件与状态）。
	eng.Process(lcResolve("nr", "net", 1))
	resumed := notifByKind(st.Notifications, "alert_resumed")
	if resumed == nil {
		t.Fatal("alert_resumed notification missing")
	}
	if resumed.SubjectID != subject {
		t.Fatalf("resumed subject %q, want %q (same subject across lifecycle)",
			resumed.SubjectID, subject)
	}
	if resumed.Fingerprint != "app/h" || resumed.AlertID == "" {
		t.Fatalf("resumed must keep alert id/fingerprint as links, got %+v", resumed)
	}
	parents := map[string]bool{}
	states := map[string]string{}
	for _, b := range resumed.Basis {
		parents[b.ParentSource] = true
		states[b.ParentSource] = b.State
		if b.ExplanationID == "" || b.ParentIncidentID == "" || b.RuleVersion == "" {
			t.Fatalf("basis must trace each cause fully, got %+v", b)
		}
	}
	if len(parents) != 2 || !parents["db"] || !parents["net"] {
		t.Fatalf("resumed basis must trace both causes, got %+v", resumed.Basis)
	}
	if states["db"] != model.ExplWithdrawn || states["net"] != model.ExplWithdrawn {
		t.Fatalf("resumed basis must show both causes withdrawn at that time, got %+v", states)
	}

	// 全程三类生命周期通知都能按同一主体串起来，且指纹可作为旁路线索。
	lifecycle := notifsWithSubject(st.Notifications, subject)
	kinds := map[string]int{}
	for _, n := range lifecycle {
		kinds[n.Kind]++
		if n.Fingerprint != "app/h" {
			t.Fatalf("every lifecycle notification must keep fingerprint: %+v", n)
		}
	}
	if kinds["alert_suppressed"] != 1 || kinds["explanation_withdrawn"] != 2 ||
		kinds["alert_resumed"] != 1 {
		t.Fatalf("lifecycle chain by subject mismatch: %+v", kinds)
	}
}

// TestReoccurrenceGetsFreshSubjectAndNoReplay：同一指纹再次发生时新事件必须有新的
// 判重身份（不得复用旧事件的抑制/恢复判重），因此新一轮抑制与恢复通知各自再发
// 一次；同轮重复回报与存储重开后重放不新增任何通知。
func TestReoccurrenceGetsFreshSubjectAndNoReplay(t *testing.T) {
	eng, st := lifecycleSetup(t)
	eng.Process(lcFire("d", "db", 1))
	eng.Process(lcFire("a", "app", 1, "db"))
	eng.Process(lcResolve("dr", "db", 1))
	oldSubject := st.LatestIncident("app/h").ID
	n1 := len(st.Notifications)
	if n1 < 3 {
		t.Fatalf("expected opened-era notifications, got %d", n1)
	}

	// 同轮重复回报（恢复后子告警无活动事件，重复观察并入旧事件不重发通知）。
	eng.Process(lcFire("a2", "app", 1, "db"))
	if len(st.Notifications) != n1 {
		t.Fatalf("same-epoch repeat must not add notifications: %d -> %d", n1, len(st.Notifications))
	}

	// 再次发生：新一轮父事件与子告警。新事件不得复用旧事件的判重身份。
	eng.Process(lcFire("d3", "db", 2))
	eng.Process(lcFire("a3", "app", 2, "db"))
	newSubject := st.LatestIncident("app/h").ID
	if newSubject == oldSubject {
		t.Fatalf("new occurrence must get a fresh incident identity, got %q", newSubject)
	}
	newSuppressed := false
	for _, n := range st.Notifications {
		if n.Kind == "alert_suppressed" && n.SubjectID == newSubject {
			newSuppressed = true
		}
		if n.Kind == "alert_suppressed" && n.SubjectID == oldSubject {
			// 旧主体的抑制通知仍应保留（历史不被改写）。
		}
	}
	if !newSuppressed {
		t.Fatal("new occurrence must emit its own suppressed notification under the new subject")
	}

	// 新轮次原因消失：新主体再发一次恢复通知，旧主体的历史不受影响。
	eng.Process(lcResolve("d4", "db", 2))
	resumedBySubject := map[string]int{}
	for _, n := range st.Notifications {
		if n.Kind == "alert_resumed" {
			resumedBySubject[n.SubjectID]++
		}
	}
	if resumedBySubject[oldSubject] != 1 || resumedBySubject[newSubject] != 1 {
		t.Fatalf("each occurrence must keep exactly one resume: %+v", resumedBySubject)
	}

	count := len(st.Notifications)
	// 存储重开后重放同一批回报：全部 duplicate，通知数不变。
	st2, err := store.Open(st.Dir())
	if err != nil {
		t.Fatal(err)
	}
	eng2 := correlator.New(st2, newRec())
	for _, a := range []model.Alert{
		lcFire("d", "db", 1), lcFire("a", "app", 1, "db"),
		lcResolve("dr", "db", 1), lcFire("d3", "db", 2),
		lcFire("a3", "app", 2, "db"), lcResolve("d4", "db", 2),
	} {
		if r, err := eng2.Process(a); err != nil || r.Outcome != correlator.OutcomeDuplicate {
			t.Fatalf("replay must be duplicate, got %v %v", r.Outcome, err)
		}
	}
	if len(st2.Notifications) != count {
		t.Fatalf("replay must not add notifications: %d -> %d", count, len(st2.Notifications))
	}
}

// TestTwoIndependentParentsWithdrawalsKeptSeparately：两个独立父事件对同一子事件
// 的原因撤回通知分别保留（按父事件身份判重），不被合并成一条。
func TestTwoIndependentParentsWithdrawalsKeptSeparately(t *testing.T) {
	eng, st := lifecycleSetup(t)
	eng.Process(lcFire("d", "db", 1))
	eng.Process(lcFire("n", "net", 1))
	eng.Process(lcFire("a", "app", 1, "db", "net"))
	eng.Process(lcResolve("dr", "db", 1))
	eng.Process(lcResolve("nr", "net", 1))

	byIncident := map[string]int{}
	for _, n := range st.Notifications {
		if n.Kind == "explanation_withdrawn" {
			byIncident[n.IncidentID]++
		}
	}
	if len(byIncident) != 2 {
		t.Fatalf("two independent parents must each keep a withdrawal, got %+v", byIncident)
	}
}
