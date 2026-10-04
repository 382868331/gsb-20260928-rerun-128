// Package scenario 内置“依赖服务故障序列”：跑完整个故障生命周期并核对
// 每个事件的开始、结束与被合并来源；通知只记录不真实发送。
package scenario

import (
	"fmt"
	"path/filepath"
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

// Run 在 dir 上执行序列，返回人可读的核对报告。
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

	rules := model.RuleSet{
		Version: "rules-v1",
		Dependencies: []model.DependencyEdge{
			{Parent: "db-01", Child: "app-01"},
			{Parent: "db-01", Child: "app-02"},
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

	type step struct {
		alert model.Alert
		want  correlator.Outcome
	}
	seq := []step{
		{fire("a1", "db-01", "ping", 1, 0), correlator.OutcomeOpened},               // 父故障开火
		{fire("a2", "db-01", "ping", 1, 1), correlator.OutcomeMerged},               // 重复告警合并
		{fire("a3", "app-01", "http", 1, 2, "db-01"), correlator.OutcomeSuppressed}, // 子告警被抑制
		{fire("a4", "app-02", "http", 1, 3, "db-01"), correlator.OutcomeSuppressed},
		{resolve("a5", "db-01", "ping", 1, 10), correlator.OutcomeResolved},      // 父故障恢复
		{fire("a6", "db-01", "ping", 2, 20), correlator.OutcomeOpened},           // 再次发生：新一轮事件
		{resolve("a7", "db-01", "ping", 1, 25), correlator.OutcomeStaleRecovery}, // 迟到恢复不得关闭新一轮
		{fire("a8", "app-01", "http", 2, 26, "db-01"), correlator.OutcomeSuppressed},
	}

	var checks []check
	for i, s := range seq {
		got, err := eng.Process(s.alert)
		if err != nil {
			return "", err
		}
		checks = append(checks, check{
			desc: fmt.Sprintf("步骤%d %s -> %s（期望 %s）", i+1, s.alert.ID, got.Outcome, s.want),
			ok:   got.Outcome == s.want,
		})
	}

	// 模拟重启：重新打开存储与引擎，抑制关系必须仍然生效。
	now = at(30)
	st2, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	eng2 := correlator.New(st2, rec)
	eng2.SetClock(nowFn)
	got, err := eng2.Process(fire("a9", "app-02", "http", 2, 31, "db-01"))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("重启后 app-02 告警仍被抑制 -> %s", got.Outcome),
		ok:   got.Outcome == correlator.OutcomeSuppressed,
	})
	got, err = eng2.Process(resolve("a10", "db-01", "ping", 2, 40))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("第二轮恢复关闭事件 -> %s", got.Outcome),
		ok:   got.Outcome == correlator.OutcomeResolved,
	})
	// 父事件恢复后，唯一原因覆盖的 a3/a4、a8/a9 被解除并重新通知。
	releasedByRecovery := st2.FindSuppression("a3").Status == model.SuppressionReleased &&
		st2.FindSuppression("a4").Status == model.SuppressionReleased &&
		st2.FindSuppression("a8").Status == model.SuppressionReleased &&
		st2.FindSuppression("a9").Status == model.SuppressionReleased
	checks = append(checks, check{
		desc: fmt.Sprintf("父恢复后唯一原因的抑制解除（a3=%s a4=%s a8=%s a9=%s）",
			st2.FindSuppression("a3").Status, st2.FindSuppression("a4").Status,
			st2.FindSuppression("a8").Status, st2.FindSuppression("a9").Status),
		ok: releasedByRecovery,
	})

	// 阶段B：父告警迟到。子告警先开立自己的事件，父告警到达后应吸收它。
	now = at(50)
	got, err = eng2.Process(fire("c1", "app-01", "http", 3, 50, "db-01"))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("父告警未到时子告警先开事件 -> %s", got.Outcome),
		ok:   got.Outcome == correlator.OutcomeOpened,
	})
	got, err = eng2.Process(fire("c2", "db-01", "ping", 3, 51))
	if err != nil {
		return "", err
	}
	lateChild := st2.Incidents[len(st2.Incidents)-2] // c1 的事件，c2 父事件在最后
	checks = append(checks, check{
		desc: fmt.Sprintf("迟到父告警开事件 -> %s，子事件状态=%s", got.Outcome, lateChild.Status),
		ok: got.Outcome == correlator.OutcomeOpened &&
			lateChild.Status == model.IncidentSuppressed,
	})

	// 阶段C：分析人员暂时解除抑制并查看证据，结束后按当前状态复判。
	ev, err := eng2.LiftSuppression("c1")
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("解除抑制查看证据：父活动=%v 边确认=%v 判定规则=%s 当前规则=%s",
			ev.ParentActive, ev.EdgeConfirmed, ev.JudgedRuleVersion, ev.CurrentRuleVersion),
		ok: ev.ParentActive && ev.EdgeConfirmed &&
			ev.JudgedRuleVersion == "rules-v1" && ev.CurrentRuleVersion == "rules-v1",
	})
	if _, err := eng2.Reevaluate(); err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("复判后 c1 抑制恢复 active（状态=%s）", st2.FindSuppression("c1").Status),
		ok:   st2.FindSuppression("c1").Status == model.SuppressionActive,
	})

	// 阶段D：规则撤回。移除 db-01->app-01 边，既有抑制须被审查解除，
	// 且记录里保留当初判断所用的规则版本。
	review, err := eng2.ApplyRules(model.RuleSet{
		Version:      "rules-v2",
		Dependencies: []model.DependencyEdge{{Parent: "db-01", Child: "app-02"}},
	})
	if err != nil {
		return "", err
	}
	released := st2.FindSuppression("c1")
	checks = append(checks, check{
		desc: fmt.Sprintf("规则撤回审查：c1=%s（判定用%s），审查报告 %d 条",
			released.Status, released.RuleVersion, len(review)),
		ok: released.Status == model.SuppressionReleased &&
			released.RuleVersion == "rules-v1" &&
			len(review) == 1,
	})

	// 阶段E：规则补回依赖边后重启，新子告警按当前规则再次被抑制。
	if _, err := eng2.ApplyRules(model.RuleSet{
		Version: "rules-v3",
		Dependencies: []model.DependencyEdge{
			{Parent: "db-01", Child: "app-01"},
			{Parent: "db-01", Child: "app-02"},
		},
	}); err != nil {
		return "", err
	}
	now = at(60)
	st3, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	eng3 := correlator.New(st3, rec)
	eng3.SetClock(nowFn)
	got, err = eng3.Process(fire("c3", "app-01", "http", 3, 60, "db-01"))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("重启后新子告警按 rules-v3 被抑制 -> %s（记录版本=%s）",
			got.Outcome, st3.FindSuppression("c3").RuleVersion),
		ok: got.Outcome == correlator.OutcomeSuppressed &&
			st3.FindSuppression("c3").RuleVersion == "rules-v3",
	})
	got, err = eng3.Process(resolve("c4", "db-01", "ping", 3, 70))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("第三轮恢复关闭事件 -> %s", got.Outcome),
		ok:   got.Outcome == correlator.OutcomeResolved,
	})

	// 阶段F：重复重放全部告警，不得产生多份通知或改动事件。
	notifBefore := len(st3.Notifications)
	recBefore := len(rec.Events)
	replayOK := true
	for _, s := range seq {
		r, err := eng3.Process(s.alert)
		if err != nil || r.Outcome != correlator.OutcomeDuplicate {
			replayOK = false
		}
	}
	for _, a := range []model.Alert{
		fire("c1", "app-01", "http", 3, 50, "db-01"),
		fire("c2", "db-01", "ping", 3, 51),
		fire("c3", "app-01", "http", 3, 60, "db-01"),
		resolve("c4", "db-01", "ping", 3, 70),
	} {
		r, err := eng3.Process(a)
		if err != nil || r.Outcome != correlator.OutcomeDuplicate {
			replayOK = false
		}
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("重放 %d 条告警均为 duplicate，通知数 %d->%d 不变",
			len(seq)+4, notifBefore, len(st3.Notifications)),
		ok: replayOK && len(st3.Notifications) == notifBefore && len(rec.Events) == recBefore,
	})

	// 核对每个事件的开始、结束与被合并来源。
	incs := st3.Incidents
	if len(incs) != 4 {
		checks = append(checks, check{desc: fmt.Sprintf("事件数=%d（期望4）", len(incs)), ok: false})
	} else {
		i1, i2, i3, i4 := incs[0], incs[1], incs[2], incs[3]
		checks = append(checks,
			check{fmt.Sprintf("事件1 %s 开始=%s 结束=%s", i1.ID,
				i1.StartedAt.Format("15:04"), i1.ResolvedAt.Format("15:04")),
				i1.StartedAt.Equal(at(0)) && i1.ResolvedAt.Equal(at(10)) && i1.Status == model.IncidentResolved},
			check{fmt.Sprintf("事件1 合并来源=%v 抑制=%v", i1.AlertIDs, i1.SuppressedAlertIDs),
				eq(i1.AlertIDs, []string{"a1", "a2"}) && eq(i1.SuppressedAlertIDs, []string{"a3", "a4"})},
			check{fmt.Sprintf("事件2 %s 开始=%s 结束=%s", i2.ID,
				i2.StartedAt.Format("15:04"), i2.ResolvedAt.Format("15:04")),
				i2.StartedAt.Equal(at(20)) && i2.ResolvedAt.Equal(at(40)) && i2.Status == model.IncidentResolved},
			check{fmt.Sprintf("事件2 合并来源=%v 抑制=%v（迟到恢复未关闭它）", i2.AlertIDs, i2.SuppressedAlertIDs),
				eq(i2.AlertIDs, []string{"a6"}) && eq(i2.SuppressedAlertIDs, []string{"a8", "a9"})},
			check{fmt.Sprintf("事件3 %s 状态=%s（父告警迟到被吸收）", i3.ID, i3.Status),
				i3.Status == model.IncidentSuppressed && i3.StartedAt.Equal(at(50))},
			check{fmt.Sprintf("事件4 %s 开始=%s 结束=%s 抑制=%v", i4.ID,
				i4.StartedAt.Format("15:04"), i4.ResolvedAt.Format("15:04"), i4.SuppressedAlertIDs),
				i4.StartedAt.Equal(at(51)) && i4.ResolvedAt.Equal(at(70)) &&
					i4.Status == model.IncidentResolved &&
					eq(i4.SuppressedAlertIDs, []string{"c1", "c3"})},
			check{fmt.Sprintf("事件规则版本=%s/%s/%s/%s", i1.RuleVersion, i2.RuleVersion, i3.RuleVersion, i4.RuleVersion),
				i1.RuleVersion == "rules-v1" && i2.RuleVersion == "rules-v1" &&
					i3.RuleVersion == "rules-v1" && i4.RuleVersion == "rules-v1"},
		)
	}
	checks = append(checks,
		check{fmt.Sprintf("原始告警独立保存 %d 条", len(st3.Alerts)), len(st3.Alerts) == 14},
		check{fmt.Sprintf("抑制关系持久化 %d 条", len(st3.Suppressions)), len(st3.Suppressions) == 6},
		check{fmt.Sprintf("通知仅写入本地记录 %d 条（内存记录一致）", len(st3.Notifications)),
			len(st3.Notifications) == 21 && len(rec.Events) == 21},
		check{fmt.Sprintf("通知决定解释只增不改 %d 条", len(st3.Explanations)),
			len(st3.Explanations) == 16},
	)

	// 阶段G：多原因关联（独立数据目录）。覆盖：交叉关联、可疑原因不压消息、
	// 预演移除、两个原因先后恢复、原因后来补到、重启、旧回报不覆盖新解释。
	gChecks, gReport, err := runMultiCause(filepath.Join(dir, "multi"), at, &now, rec)
	if err != nil {
		return "", err
	}
	checks = append(checks, gChecks...)

	var b strings.Builder
	b.WriteString("依赖服务故障序列核对报告\n")
	failed := 0
	for _, c := range checks {
		mark := "PASS"
		if !c.ok {
			mark = "FAIL"
			failed++
		}
		fmt.Fprintf(&b, "[%s] %s\n", mark, c.desc)
	}
	b.WriteString(gReport)
	fmt.Fprintf(&b, "结果: %d 通过, %d 失败\n", len(checks)-failed, failed)
	if failed > 0 {
		return b.String(), fmt.Errorf("%d 项核对失败", failed)
	}
	return b.String(), nil
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// runMultiCause 阶段G：多原因关联序列。同一告警被两个独立原因覆盖，
// 核对可疑原因不压消息、预演移除、两个原因先后恢复、原因后来补到、
// 重启后状态可追溯、旧回报不覆盖新解释。
func runMultiCause(dir string, at func(int) time.Time, now *time.Time, rec *notify.Recording) ([]check, string, error) {
	var checks []check
	nowFn := func() time.Time { return *now }

	st, err := store.Open(dir)
	if err != nil {
		return nil, "", err
	}
	eng := correlator.New(st, rec)
	eng.SetClock(nowFn)
	if err := st.SaveRules(model.RuleSet{
		Version: "multi-v1",
		Dependencies: []model.DependencyEdge{
			{Parent: "db", Child: "web"},
			{Parent: "cache", Child: "web"},
		},
	}); err != nil {
		return nil, "", err
	}

	fire := func(id, src string, epoch, min int, deps ...string) model.Alert {
		return model.Alert{ID: id, Source: src, Check: "chk", Severity: "critical",
			Status: model.StatusFiring, Epoch: epoch, StartsAt: at(min), DependsOn: deps}
	}
	resolve := func(id, src string, epoch, min int) model.Alert {
		return model.Alert{ID: id, Source: src, Check: "chk", Severity: "critical",
			Status: model.StatusResolved, Epoch: epoch, StartsAt: at(min)}
	}
	process := func(a model.Alert) correlator.Outcome {
		r, err := eng.Process(a)
		if err != nil {
			return correlator.Outcome("error:" + err.Error())
		}
		return r.Outcome
	}

	// 交叉关联：web 同时依赖 db 与 cache 两个独立父原因。
	*now = at(100)
	got := process(fire("m1", "db", 1, 100))
	got2 := process(fire("m2", "cache", 1, 100))
	checks = append(checks, check{
		desc: fmt.Sprintf("G1 两个独立父事件开立 -> %s/%s，注册 2 个已确认原因", got, got2),
		ok: got == correlator.OutcomeOpened && got2 == correlator.OutcomeOpened &&
			len(st.Causes) == 2 &&
			st.Causes[0].Status == model.CauseConfirmed && st.Causes[1].Status == model.CauseConfirmed,
	})
	got = process(fire("m3", "web", 1, 101, "db", "cache"))
	x := st.CurrentExplanation("m3")
	checks = append(checks, check{
		desc: fmt.Sprintf("G2 web 告警被两个原因交叉抑制 -> %s（抑制 %d 条，解释 %v）",
			got, len(st.SuppressionsFor("m3")), x.CauseIDs),
		ok: got == correlator.OutcomeSuppressed && len(st.SuppressionsFor("m3")) == 2 &&
			x.Decision == "suppressed" && len(x.CauseIDs) == 2,
	})
	// 独立告警不受原因层影响，仍及时通知。
	notifBefore := len(st.Notifications)
	got = process(fire("m4", "solo", 1, 102))
	checks = append(checks, check{
		desc: fmt.Sprintf("G3 独立告警仍及时通知 -> %s", got),
		ok:   got == correlator.OutcomeOpened && len(st.Notifications) == notifBefore+1,
	})
	// 重复观察不增加虚假原因。
	dup1 := process(fire("m1", "db", 1, 100))
	dup2 := process(fire("m3", "web", 1, 101, "db", "cache"))
	checks = append(checks, check{
		desc: fmt.Sprintf("G4 重复观察 -> %s/%s，原因数仍为 %d", dup1, dup2, len(st.Causes)),
		ok: dup1 == correlator.OutcomeDuplicate && dup2 == correlator.OutcomeDuplicate &&
			len(st.Causes) == 3, // m1/m2/m4 各一个，重放不新增
	})
	// 可疑（待核实）原因不压掉任何后续消息。
	if _, _, err := eng.ReportCause("rumor-1", "疑似网络抖动", "net"); err != nil {
		return nil, "", err
	}
	notifBefore = len(st.Notifications)
	got = process(fire("m5", "solo2", 1, 103))
	pendingAffects := -1
	for _, v := range eng.CauseViews() {
		if v.Cause.ID == "rumor-1" {
			pendingAffects = len(v.AffectedAlertIDs)
		}
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("G5 可疑原因待核实，后续告警仍通知 -> %s（影响告警 %d 条）", got, pendingAffects),
		ok: got == correlator.OutcomeOpened && pendingAffects == 0 &&
			len(st.Notifications) == notifBefore+1,
	})
	// 预演移除 db 原因：web 仍被 cache 覆盖，预演不落任何状态。
	causeDB := st.FindCauseByIncident("inc-db/chk-1").ID
	notifBefore = len(st.Notifications)
	expBefore := len(st.Explanations)
	preview, err := eng.PreviewRemoveCause(causeDB)
	if err != nil {
		return nil, "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("G6 预演移除 db 原因：重新通知=%v 保持=%v（状态未变）",
			preview.WouldRelease, preview.WouldKeep),
		ok: len(preview.WouldRelease) == 0 && eq(preview.WouldKeep, []string{"m3"}) &&
			len(st.Notifications) == notifBefore && len(st.Explanations) == expBefore &&
			st.FindCause(causeDB).Status == model.CauseConfirmed &&
			len(st.SuppressionsFor("m3")) == 2,
	})
	// 第一个原因恢复：仍有 cache 覆盖，不重新通知。
	notifBefore = len(st.Notifications)
	got = process(resolve("m6", "db", 1, 110))
	x = st.CurrentExplanation("m3")
	checks = append(checks, check{
		desc: fmt.Sprintf("G7 db 恢复但 cache 仍覆盖，不重新通知 -> %s（通知 +%d，解释=%s）",
			got, len(st.Notifications)-notifBefore, x.Decision),
		ok: got == correlator.OutcomeResolved &&
			len(st.Notifications) == notifBefore+1 && // 仅 incident_resolved 一条
			len(st.SuppressionsFor("m3")) == 1 &&
			x.Decision == "suppressed" &&
			st.FindCause(causeDB).Status == model.CauseWithdrawn,
	})
	// 第二个原因恢复：不再有任何已确认原因，才改变通知决定。
	got = process(resolve("m7", "cache", 1, 120))
	x = st.CurrentExplanation("m3")
	releasedNotif := false
	for _, n := range st.Notifications {
		if n.Kind == "alert_released" && strings.Contains(n.Detail, "m3") {
			releasedNotif = true
		}
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("G8 cache 也恢复，m3 解除并重新通知 -> %s（解释=%s）", got, x.Decision),
		ok: got == correlator.OutcomeResolved && releasedNotif && x.Decision == "released" &&
			len(st.SuppressionsFor("m3")) == 0,
	})
	// 原因后来补到：web 先开立并通知，迟到父事件到达后吸收为抑制。
	got = process(fire("m8", "web", 2, 130, "db"))
	openedNotif := len(st.Notifications)
	got2 = process(fire("m9", "db", 2, 131))
	lateChild := st.Incidents[len(st.Incidents)-2]
	x = st.CurrentExplanation("m8")
	checks = append(checks, check{
		desc: fmt.Sprintf("G9 原因后来补到：m8 先通知，迟到父事件吸收 -> %s/%s（子事件=%s，解释=%s）",
			got, got2, lateChild.Status, x.Decision),
		ok: got == correlator.OutcomeOpened && got2 == correlator.OutcomeOpened &&
			lateChild.Status == model.IncidentSuppressed && x.Decision == "suppressed",
	})
	// 已发出的通知保留原依据。
	keptBasis := false
	for _, n := range st.Notifications {
		if n.Kind == "incident_opened" && strings.Contains(n.Detail, "web/chk epoch 2") {
			keptBasis = true
		}
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("G10 已发出通知保留原依据（incident_opened 仍在，通知数 %d）", openedNotif),
		ok:   keptBasis,
	})
	// 进程重开：原因状态与解释历史可追溯。
	*now = at(140)
	expCount := len(st.Explanations)
	st2, err := store.Open(dir)
	if err != nil {
		return nil, "", err
	}
	eng2 := correlator.New(st2, rec)
	eng2.SetClock(nowFn)
	views := eng2.CauseViews()
	var nConfirmed, nPending, nWithdrawn int
	for _, v := range views {
		switch v.Cause.Status {
		case model.CauseConfirmed:
			nConfirmed++
		case model.CausePending:
			nPending++
		case model.CauseWithdrawn:
			nWithdrawn++
		}
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("G11 重启后原因状态可追溯：已确认=%d 待核实=%d 被撤回=%d，解释 %d->%d 条",
			nConfirmed, nPending, nWithdrawn, expCount, len(st2.Explanations)),
		ok: nConfirmed == 4 && nPending == 1 && nWithdrawn == 2 &&
			len(st2.Explanations) == expCount,
	})
	// 旧决定的回报不能覆盖新解释。
	cur := st2.CurrentExplanation("m3")
	applied, err := eng2.SubmitDecisionReport("m3", cur.Seq, "suppressed", "旧依据：db 故障")
	if err != nil {
		return nil, "", err
	}
	after := st2.CurrentExplanation("m3")
	checks = append(checks, check{
		desc: fmt.Sprintf("G12 旧回报被拒绝：applied=%v，当前解释仍为 seq=%d %s",
			applied, after.Seq, after.Decision),
		ok: !applied && after.Seq == cur.Seq && after.Decision == cur.Decision,
	})
	// 关联范围收窄：撤回 db->web 边，m8 解除且原因历史留下收窄记录。
	if _, err := eng2.ApplyRules(model.RuleSet{
		Version:      "multi-v2",
		Dependencies: []model.DependencyEdge{{Parent: "cache", Child: "web"}},
	}); err != nil {
		return nil, "", err
	}
	causeDB2 := st2.FindCauseByIncident("inc-db/chk-2")
	narrowed := false
	for _, h := range causeDB2.History {
		if h.Kind == "scope_narrowed" {
			narrowed = true
		}
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("G13 关联范围收窄：m8 抑制解除（%d 条活动），原因历史含收窄记录=%v",
			len(st2.SuppressionsFor("m8")), narrowed),
		ok: len(st2.SuppressionsFor("m8")) == 0 && narrowed,
	})
	// 再次重放：不产生虚假原因与多余通知。
	causeCount := len(st2.Causes)
	notifBefore = len(st2.Notifications)
	replayOK := true
	for _, a := range []model.Alert{
		fire("m1", "db", 1, 100), fire("m2", "cache", 1, 100),
		fire("m3", "web", 1, 101, "db", "cache"), resolve("m6", "db", 1, 110),
		resolve("m7", "cache", 1, 120), fire("m8", "web", 2, 130, "db"), fire("m9", "db", 2, 131),
	} {
		r, err := eng2.Process(a)
		if err != nil || r.Outcome != correlator.OutcomeDuplicate {
			replayOK = false
		}
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("G14 重放不增虚假原因与通知（原因 %d，通知 +%d）",
			len(st2.Causes), len(st2.Notifications)-notifBefore),
		ok: replayOK && len(st2.Causes) == causeCount && len(st2.Notifications) == notifBefore,
	})

	// 可查看状态汇总：每个原因的当前状态与影响告警。
	var b strings.Builder
	b.WriteString("多原因关联当前状态：\n")
	for _, v := range eng2.CauseViews() {
		fmt.Fprintf(&b, "  原因 %s [%s] 影响告警=%v（历史 %d 条）\n",
			v.Cause.ID, v.Cause.Status, v.AffectedAlertIDs, len(v.Cause.History))
	}
	return checks, b.String(), nil
}
