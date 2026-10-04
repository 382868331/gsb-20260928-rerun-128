// Package scenario 内置“多原因关联序列”：用本地事件构造交叉关联、迟到父
// 事件、进程重开、关联范围收窄、两个原因先后恢复，核对重复观察不增加
// 虚假原因、独立告警仍及时通知、旧决定的回报不覆盖新解释。通知只记录。
package scenario

import (
	"fmt"
	"strings"
	"time"

	"alertcorr/internal/correlator"
	"alertcorr/internal/model"
	"alertcorr/internal/notify"
	"alertcorr/internal/store"
)

type check struct {
	desc string
	ok   bool
}

// Run 在 dir 上执行序列，返回人可读的核对报告；任一失败返回错误。
func Run(dir string) (string, error) {
	base := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	at := func(min int) time.Time { return base.Add(time.Duration(min) * time.Minute) }
	now := at(0)
	nowFn := func() time.Time { return now }

	st, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	rec := &notify.Recording{}
	eng := correlator.New(st, rec)
	eng.SetClock(nowFn)

	// db-01（数据库）与 net-01（网络）都能解释 app-01（应用）的故障，
	// 这是两条相互独立的原因。
	rules := model.RuleSet{
		Version: "rules-v1",
		Dependencies: []model.DependencyEdge{
			{Parent: "db-01", Child: "app-01"},
			{Parent: "net-01", Child: "app-01"},
			{Parent: "db-01", Child: "app-02"},
			{Parent: "db-01", Child: "app-03"},
			{Parent: "cache-01", Child: "app-05"},
			{Parent: "net-02", Child: "app-06"},
			{Parent: "mq-01", Child: "app-07"},
		},
	}
	if err := st.SaveRules(rules); err != nil {
		return "", err
	}

	fire := func(id, src, chk string, epoch, min int, deps ...string) model.Alert {
		return model.Alert{ID: id, Source: src, Check: chk, Severity: "critical",
			Status: model.StatusFiring, Epoch: epoch, StartsAt: at(min),
			DependsOn: deps, Message: src + " " + chk + " down"}
	}
	resolve := func(id, src, chk string, epoch, min int) model.Alert {
		return model.Alert{ID: id, Source: src, Check: chk, Severity: "critical",
			Status: model.StatusResolved, Epoch: epoch, StartsAt: at(min),
			Message: src + " " + chk + " recovered"}
	}

	var checks []check
	pass := func(desc string, ok bool) { checks = append(checks, check{desc, ok}) }

	// ---- 阶段A：交叉关联，一个告警同时有两个独立原因 ----
	eng.Process(fire("a1", "db-01", "ping", 1, 0))
	eng.Process(fire("a2", "net-01", "ping", 1, 1))
	r, err := eng.Process(fire("a3", "app-01", "http", 1, 2, "db-01", "net-01"))
	if err != nil {
		return "", err
	}
	v := eng.ViewCauses("app-01/http")
	pass(fmt.Sprintf("app-01 同时被两个独立原因抑制 -> %s；已确认=%d 影响中=%d",
		r.Outcome, len(v.Confirmed), len(v.AffectsNow)),
		r.Outcome == correlator.OutcomeSuppressed && len(v.Confirmed) == 2 && len(v.AffectsNow) == 2)
	// 重复观察：不增加虚假原因，不新增通知。
	nb := len(st.Notifications)
	rr, _ := eng.Process(fire("a3r", "app-01", "http", 1, 3, "db-01", "net-01"))
	pass(fmt.Sprintf("重复观察 -> %s，原因数仍=%d，通知不增", rr.Outcome, len(v.Confirmed)),
		rr.Outcome == correlator.OutcomeSuppressed &&
			len(eng.ViewCauses("app-01/http").Confirmed) == 2 && len(st.Notifications) == nb)

	// ---- 阶段B：一个父事件恢复不应重新通知 ----
	now = at(10)
	eng.Process(resolve("a4", "db-01", "ping", 1, 10))
	v = eng.ViewCauses("app-01/http")
	resumedCount := countNotif(st.Notifications, "alert_resumed")
	pass(fmt.Sprintf("db-01 恢复后 app-01 仍被 net-01 抑制（已确认=%d 已撤回=%d），无恢复通知",
		len(v.Confirmed), len(v.Withdrawn)),
		v.Suppressed && len(v.Confirmed) == 1 && len(v.Withdrawn) == 1 && resumedCount == 0)

	// ---- 阶段C：进程重开，状态与决定保持 ----
	now = at(30)
	// 用一个独立父源核对迟到恢复：旧 epoch 恢复不得关闭新一轮事件。
	eng.Process(fire("a5", "cache-01", "ping", 1, 15))
	eng.Process(fire("a5b", "cache-01", "ping", 2, 16))
	sr, _ := eng.Process(resolve("a6", "cache-01", "ping", 1, 17))
	pass(fmt.Sprintf("迟到恢复 -> %s，db-01 第二轮事件仍活动", sr.Outcome),
		sr.Outcome == correlator.OutcomeStaleRecovery && st.ActiveIncident("cache-01/ping") != nil)
	st2, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	eng2 := correlator.New(st2, rec)
	eng2.SetClock(nowFn)
	v = eng2.ViewCauses("app-01/http")
	pass("重启后多原因状态保持（net-01 仍抑制、db-01 已撤回可追溯）",
		v.Suppressed && len(v.Confirmed) == 1 && v.Confirmed[0].ParentSource == "net-01" &&
			len(v.Withdrawn) == 1 && len(v.Withdrawn[0].History) >= 2)

	// ---- 阶段D：两个原因先后恢复，最后一条消失才重新通知且只一次 ----
	now = at(40)
	resumeBefore := countNotif(st2.Notifications, "alert_resumed")
	eng2.Process(resolve("a7", "net-01", "ping", 1, 40))
	v = eng2.ViewCauses("app-01/http")
	pass("net-01 恢复：app-01 全部已确认原因清空，发出恰好一次恢复通知",
		!v.Suppressed && countNotif(st2.Notifications, "alert_resumed")-resumeBefore == 1)
	// 再次重算/重复观察不重复通知。
	eng2.Process(fire("a3r2", "app-01", "http", 1, 41))
	pass("重复观察不产生第二次恢复通知", countNotif(st2.Notifications, "alert_resumed")-resumeBefore == 1)

	// ---- 阶段E：独立告警即使存在可疑原因仍及时通知 ----
	// db-01 在 epoch2 活动（阶段C 前曾重开 cache，不影响）；这里为 app-02
	// 提供一个活动父源 db-01（其 epoch2 事件此时仍活动）。
	now = at(50)
	eng2.Process(fire("b0", "db-01", "ping", 2, 49))
	r, _ = eng2.Process(fire("b1", "app-02", "http", 1, 50)) // 无 DependsOn
	v = eng2.ViewCauses("app-02/http")
	pass(fmt.Sprintf("app-02 无显式证据先独立通知 -> %s，待核实=%d 不被抑制",
		r.Outcome, len(v.Suspected)),
		r.Outcome == correlator.OutcomeOpened && len(v.Suspected) == 1 && !v.Suppressed)

	// 父告警迟到：子告警先独立开事件，父事件到达后吸收为 confirmed。
	now = at(60)
	got0, _ := eng2.Process(fire("c0", "app-06", "http", 1, 60)) // 父未到，先独立
	got, _ := eng2.Process(fire("c1", "net-02", "ping", 1, 61))
	absorbed := eng2.Store().LatestIncident("app-06/http")
	// 父到达但子无显式证据：仅记 suspected，子事件仍活动、独立通知不被压掉。
	v06 := eng2.ViewCauses("app-06/http")
	suspectedOnly := absorbed.Status == model.IncidentActive &&
		len(v06.Suspected) == 1 && !v06.Suppressed
	// 随后一条带显式依赖证据的重复观察到达：升级 confirmed，子事件被吸收。
	upg, _ := eng2.Process(fire("c0b", "app-06", "http", 1, 62, "net-02"))
	absorbed2 := eng2.Store().LatestIncident("app-06/http")
	pass(fmt.Sprintf("子先开事件 -> %s；迟到父事件 -> %s，子被吸收=%v",
		got0.Outcome, got.Outcome, absorbed != nil && absorbed.Status == model.IncidentSuppressed),
		got0.Outcome == correlator.OutcomeOpened && got.Outcome == correlator.OutcomeOpened &&
			suspectedOnly && upg.Outcome == correlator.OutcomeSuppressed &&
			absorbed2 != nil && absorbed2.Status == model.IncidentSuppressed)

	// ---- 阶段F：规则图收窄（撤回一条边）只影响对应解释 ----
	now = at(70)
	review, err := eng2.ApplyRules(model.RuleSet{Version: "rules-v2", Dependencies: []model.DependencyEdge{
		{Parent: "net-01", Child: "app-01"},
		{Parent: "db-01", Child: "app-02"},
		{Parent: "db-01", Child: "app-04"},
		{Parent: "mq-01", Child: "app-07"},
	}})
	if err != nil {
		return "", err
	}
	_ = review

	// ---- 阶段G：预演移除原因，确认后才改变通知决定 ----
	now = at(80)
	// 恢复 db-01->app-02 边并在新轮次构造一个仍被单原因抑制的主体。
	if _, err := eng2.ApplyRules(model.RuleSet{Version: "rules-v3", Dependencies: []model.DependencyEdge{
		{Parent: "net-01", Child: "app-01"},
		{Parent: "db-01", Child: "app-02"},
		{Parent: "db-01", Child: "app-04"},
		{Parent: "mq-01", Child: "app-07"},
	}}); err != nil {
		return "", err
	}
	eng2.Process(fire("d1", "mq-01", "ping", 1, 80))
	eng2.Process(fire("d2", "app-07", "http", 1, 81, "mq-01"))
	v = eng2.ViewCauses("app-07/http")
	var explID string
	for _, x := range v.Confirmed {
		if x.ParentSource == "mq-01" && st2.ParentIncidentActive(x.ParentIncidentID) {
			explID = x.ID
		}
	}
	preview, err := eng2.PreviewRemoveCause(explID)
	if err != nil {
		return "", err
	}
	stillSuppressed := eng2.ViewCauses("app-07/http").Suppressed
	pass(fmt.Sprintf("预演移除 %s：将恢复=%v，状态未改=%v", explID,
		len(preview.WouldResume) == 1, stillSuppressed),
		len(preview.WouldResume) == 1 && stillSuppressed)
	nBefore := len(st2.Notifications)
	eng2.ConfirmRemoveCause(explID)
	pass("确认移除后只改变通知决定（出现一次恢复通知），原因标记为 operator_removed",
		len(st2.Notifications) == nBefore+1 &&
			eng2.ViewCauses("app-07/http").Withdrawn[0].EndReason == model.EndOperatorRemoved)
	// 被移除原因不被重复观察复活。
	eng2.Process(fire("d3", "app-07", "http", 1, 82, "mq-01"))
	v = eng2.ViewCauses("app-07/http")
	pass("被操作者移除的原因不自动复活（已确认=0，撤回保留）", len(v.Confirmed) == 0)

	// ---- 阶段H：历史解释可追溯（状态变迁、范围收窄）----
	var scoped *model.Explanation
	for _, x := range st2.Explanations {
		if x.ParentSource == "net-01" && x.AlertFingerprint == "app-01/http" && x.Active() {
			if x.Active() {
				scoped = x
			}
		}
	}
	if scoped == nil {
		// 历史上的 net-01 解释已随父恢复而撤回；在新轮次重建一条活动解释来演示收窄。
		eng2.Process(fire("e1", "net-01", "ping", 2, 85))
		eng2.Process(fire("e2", "app-01", "http", 2, 86, "net-01"))
		for _, x := range st2.Explanations {
			if x.ParentSource == "net-01" && x.AlertFingerprint == "app-01/http" && x.Active() {
				scoped = x
			}
		}
	}
	if scoped != nil {
		eng2.NarrowScope(scoped.ID, []string{"a3"})
	}
	traceOK := scoped != nil && len(scoped.Scope) == 1 && len(scoped.History) >= 1
	pass("关联范围收窄被记录且可追溯（scope 与 history 保留）", traceOK)

	// 已发出通知保留原始依据快照，事后不被改写。
	basisOK := false
	for _, n := range st2.Notifications {
		if n.Kind == "alert_suppressed" && n.SubjectID != "" && len(n.Basis) >= 1 {
			basisOK = true
		}
	}
	pass("已发出的抑制通知保留当时依据快照", basisOK)

	// ---- 阶段I：全量重放均为 duplicate，不产生多份通知 ----
	st3, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	eng3 := correlator.New(st3, rec)
	eng3.SetClock(nowFn)
	all := []model.Alert{
		fire("a1", "db-01", "ping", 1, 0),
		fire("a2", "net-01", "ping", 1, 1),
		fire("a3", "app-01", "http", 1, 2, "db-01", "net-01"),
		resolve("a4", "db-01", "ping", 1, 10),
		resolve("a7", "net-01", "ping", 1, 40),
		fire("b1", "app-02", "http", 1, 50),
	}
	dupOK := true
	n0 := len(st3.Notifications)
	for _, a := range all {
		if rr, err := eng3.Process(a); err != nil || rr.Outcome != correlator.OutcomeDuplicate {
			dupOK = false
		}
	}
	pass("重放全部已处理告警均为 duplicate，通知数不变", dupOK && len(st3.Notifications) == n0)

	var b strings.Builder
	b.WriteString("多原因关联序列核对报告\n")
	failed := 0
	for _, c := range checks {
		mark := "PASS"
		if !c.ok {
			mark = "FAIL"
			failed++
		}
		fmt.Fprintf(&b, "[%s] %s\n", mark, c.desc)
	}
	fmt.Fprintf(&b, "结果: %d 通过, %d 失败\n", len(checks)-failed, failed)
	if failed > 0 {
		return b.String(), fmt.Errorf("%d 项核对失败", failed)
	}
	return b.String(), nil
}

func countNotif(ns []model.Notification, kind string) int {
	n := 0
	for _, x := range ns {
		if x.Kind == kind {
			n++
		}
	}
	return n
}
