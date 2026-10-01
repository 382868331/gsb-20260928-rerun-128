// Package scenario 内置“依赖服务故障序列”：跑完整个故障生命周期并核对
// 每个事件的开始、结束与被合并来源；通知只写本地记录，不真实发送。
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
	rec, err := notify.NewFileRecording(dir)
	if err != nil {
		return "", err
	}
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

	// 模拟重启：重新打开存储、通知记录与引擎，抑制关系必须仍然生效。
	now = at(30)
	st2, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	rec2, err := notify.NewFileRecording(dir)
	if err != nil {
		return "", err
	}
	eng2 := correlator.New(st2, rec2)
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

	// 核对第一、二轮事件。
	incs := st2.Incidents
	if len(incs) != 2 {
		checks = append(checks, check{desc: fmt.Sprintf("第一二轮事件数=%d（期望2）", len(incs)), ok: false})
	} else {
		i1, i2 := incs[0], incs[1]
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
			check{fmt.Sprintf("事件规则版本=%s/%s", i1.RuleVersion, i2.RuleVersion),
				i1.RuleVersion == "rules-v1" && i2.RuleVersion == "rules-v1"},
		)
	}

	// ---- 第三轮：父告警迟到、分析人员解除/重判、规则撤回、重启后新子告警 ----
	now = at(50)
	// 子告警先到：父事件未活动，只能独立成事件。
	got, err = eng2.Process(fire("c1", "app-01", "http", 3, 50, "db-01"))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("父告警未到时子告警独立成事件 -> %s", got.Outcome),
		ok:   got.Outcome == correlator.OutcomeOpened,
	})
	// 父告警迟到：开火后应按依赖证据把 c1 改判为抑制。
	got, err = eng2.Process(fire("p1", "db-01", "ping", 3, 51))
	if err != nil {
		return "", err
	}
	sup := st2.FindSuppression("c1")
	checks = append(checks,
		check{fmt.Sprintf("迟到父告警开火 -> %s", got.Outcome), got.Outcome == correlator.OutcomeOpened},
		check{fmt.Sprintf("c1 被迟到父告警改判抑制（规则版本 %s）", supRuleVersion(sup)),
			sup != nil && sup.Status == model.SuppressionActive && sup.RuleVersion == "rules-v1"},
	)
	// 分析人员暂时解除抑制并查看证据。
	ev, err := eng2.LiftSuppression("c1")
	liftOK := err == nil && ev != nil && ev.EdgeConfirmed && ev.RuleVersion == "rules-v1" &&
		ev.Parent != nil && ev.Parent.Source == "db-01"
	checks = append(checks, check{
		desc: fmt.Sprintf("解除 c1 抑制并查看证据（原判断规则版本 %s）", evRuleVersion(ev)),
		ok:   liftOK,
	})
	// 操作结束重判：边仍确认且父事件仍活动，恢复抑制。
	if err := eng2.RejudgeSuppression("c1"); err != nil {
		return "", err
	}
	sup = st2.FindSuppression("c1")
	checks = append(checks, check{
		desc: fmt.Sprintf("重判后 c1 恢复抑制 -> %s", supStatus(sup)),
		ok:   sup != nil && sup.Status == model.SuppressionActive,
	})
	// 规则撤回：rules-v2 撤销 db-01 -> app-01 边，影响审查应解除 c1 抑制。
	now = at(60)
	rulesV2 := model.RuleSet{
		Version:      "rules-v2",
		Dependencies: []model.DependencyEdge{{Parent: "db-01", Child: "app-02"}},
	}
	if err := eng2.ReviewRules(rulesV2); err != nil {
		return "", err
	}
	sup = st2.FindSuppression("c1")
	childInc := st2.ActiveIncident("app-01/http")
	checks = append(checks,
		check{fmt.Sprintf("规则撤回后 c1 抑制解除 -> %s（原因 %s）", supStatus(sup), supReason(sup)),
			sup != nil && sup.Status == model.SuppressionReleased},
		check{"c1 解除后重新立为活动事件", childInc != nil},
		check{fmt.Sprintf("原判断规则版本仍保留为 %s", supRuleVersion(sup)),
			sup != nil && sup.RuleVersion == "rules-v1"},
	)
	// 再次重启：新引擎 + 本地通知记录重放同一条告警不产生多份通知。
	now = at(70)
	st3, err := store.Open(dir)
	if err != nil {
		return "", err
	}
	rec3, err := notify.NewFileRecording(dir)
	if err != nil {
		return "", err
	}
	eng3 := correlator.New(st3, rec3)
	eng3.SetClock(nowFn)
	got, err = eng3.Process(fire("c2", "app-02", "http", 3, 71, "db-01"))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("重启后新子告警 c2 仍按 rules-v2 抑制 -> %s", got.Outcome),
		ok:   got.Outcome == correlator.OutcomeSuppressed,
	})
	before := len(rec3.Events())
	got, err = eng3.Process(fire("c2", "app-02", "http", 3, 71, "db-01"))
	if err != nil {
		return "", err
	}
	checks = append(checks,
		check{fmt.Sprintf("重复重放 c2 -> %s", got.Outcome), got.Outcome == correlator.OutcomeReplayed},
		check{fmt.Sprintf("重放后通知数不变（%d 条）", len(rec3.Events())), len(rec3.Events()) == before},
	)
	got, err = eng3.Process(resolve("p2", "db-01", "ping", 3, 80))
	if err != nil {
		return "", err
	}
	checks = append(checks, check{
		desc: fmt.Sprintf("第三轮恢复关闭事件 -> %s", got.Outcome),
		ok:   got.Outcome == correlator.OutcomeResolved,
	})

	checks = append(checks,
		check{fmt.Sprintf("原始告警独立保存 %d 条", len(st3.Alerts)), len(st3.Alerts) == 14},
		check{fmt.Sprintf("抑制关系持久化 %d 条", len(st3.Suppressions)), len(st3.Suppressions) == 6},
		check{fmt.Sprintf("影响审查审计 %d 条", len(st3.Reviews)), len(st3.Reviews) >= 4},
		check{fmt.Sprintf("通知仅写本地记录 %d 条", len(rec3.Events())), len(rec3.Events()) == 17},
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

func supRuleVersion(s *model.Suppression) string {
	if s == nil {
		return "<none>"
	}
	return s.RuleVersion
}

func supStatus(s *model.Suppression) string {
	if s == nil {
		return "<none>"
	}
	return s.Status
}

func supReason(s *model.Suppression) string {
	if s == nil {
		return "<none>"
	}
	return s.Reason
}

func evRuleVersion(ev *correlator.Evidence) string {
	if ev == nil {
		return "<none>"
	}
	return ev.RuleVersion
}
