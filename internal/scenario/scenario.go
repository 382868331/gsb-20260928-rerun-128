// Package scenario 内置“依赖服务故障序列”：跑完整个故障生命周期并核对
// 每个事件的开始、结束与被合并来源；通知只记录不真实发送。
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
	kept := st2.FindSuppression("a4")
	checks = append(checks, check{
		desc: fmt.Sprintf("规则撤回审查：c1=%s（判定用%s）a4=%s",
			released.Status, released.RuleVersion, kept.Status),
		ok: released.Status == model.SuppressionReleased &&
			released.RuleVersion == "rules-v1" &&
			kept.Status == model.SuppressionActive && len(review) > 0,
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
			len(st3.Notifications) == 18 && len(rec.Events) == 18},
	)

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
