package engine_test

import (
	"path/filepath"
	"testing"
	"time"

	"alertcorr/internal/engine"
	"alertcorr/internal/model"
	"alertcorr/internal/notify"
	"alertcorr/internal/scenario"
	"alertcorr/internal/store"
)

func ingest(t *testing.T, eng *engine.Engine, alerts []model.Alert) {
	t.Helper()
	for _, a := range alerts {
		if err := eng.Ingest(a); err != nil {
			t.Fatalf("ingest %s: %v", a.ID, err)
		}
	}
}

func roles(ev *model.Event) map[string]string {
	m := map[string]string{}
	for _, s := range ev.Sources {
		m[s.AlertID] = s.Role
	}
	return m
}

func TestCorrelationScenario(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	sink := notify.NewRecordingSink()
	eng := engine.New(store.New(dir), sink)
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	if err := eng.PublishRules(scenario.Rules()); err != nil {
		t.Fatal(err)
	}

	ingest(t, eng, scenario.Phase1())
	alerts := eng.Alerts()
	if len(alerts) != 7 {
		t.Fatalf("原始告警应原样保存 7 条，实际 %d", len(alerts))
	}

	events := eng.Events()
	if len(events) != 1 {
		t.Fatalf("第一轮应只产生 1 个事件，实际 %d", len(events))
	}
	ev := events[0]
	if ev.RootService != "db" || ev.Status != model.EventResolved {
		t.Fatalf("事件根因应为 db 且已恢复，实际 %s/%s", ev.RootService, ev.Status)
	}
	if ev.OpenedAt.Minute() != 0 || ev.ResolvedAt.Minute() != 12 {
		t.Fatalf("事件开始/结束时间应为 10:00/10:12，实际 %s/%s", ev.OpenedAt, ev.ResolvedAt)
	}
	r := roles(ev)
	if r["a-db-1"] != "root" || r["a-db-1-dup"] != "duplicate" ||
		r["a-api-1"] != "suppressed_child" || r["a-web-1"] != "suppressed_child" {
		t.Fatalf("来源角色错误: %v", r)
	}
	if len(ev.Suppressions) != 2 {
		t.Fatalf("应有 2 条显式依赖抑制证据，实际 %d", len(ev.Suppressions))
	}
	for _, s := range ev.Suppressions {
		if s.ParentEventID != ev.ID || s.RuleVersion != scenario.RuleVersion || s.Reason == "" {
			t.Fatalf("抑制证据缺失父事件/规则版本/理由: %+v", s)
		}
	}

	kinds := map[string]int{}
	for _, m := range sink.Log() {
		kinds[m.Kind]++
	}
	if kinds["event_opened"] != 1 || kinds["event_resolved"] != 1 || kinds["child_suppressed"] != 2 {
		t.Fatalf("通知录制计数错误: %v（仅录制，不外发）", kinds)
	}

	// 模拟重启：新建引擎从磁盘加载，抑制关系必须保留，且不重发通知。
	sink2 := notify.NewRecordingSink()
	eng2 := engine.New(store.New(dir), sink2)
	if err := eng2.Load(); err != nil {
		t.Fatal(err)
	}
	reloaded := eng2.Events()
	if len(reloaded) != 1 || len(reloaded[0].Suppressions) != 2 {
		t.Fatalf("重启后抑制关系丢失: %+v", reloaded)
	}
	if len(sink2.Log()) != 0 {
		t.Fatalf("单纯重启加载不应产生通知，实际 %d 条", len(sink2.Log()))
	}

	ingest(t, eng2, scenario.Phase2())
	final := eng2.Events()
	if len(final) != 2 {
		t.Fatalf("再次发生应产生第 2 个事件，实际 %d", len(final))
	}
	var round1, round2 *model.Event
	for _, ev := range final {
		switch ev.TriggerStartsAt.Minute() {
		case 0:
			round1 = ev
		case 20:
			round2 = ev
		}
	}
	if round1 == nil || round2 == nil {
		t.Fatalf("两轮事件身份缺失")
	}
	if round1.Status != model.EventResolved || round2.Status != model.EventResolved {
		t.Fatalf("两轮最终均应已恢复: %s/%s", round1.Status, round2.Status)
	}
	if round2.ResolvedAt.Minute() != 30 {
		t.Fatalf("第 2 轮必须由自己的恢复在 10:30 关闭，实际 %s", round2.ResolvedAt)
	}
	if !contains(eng2.UnmatchedResolves, "a-db-1-late-res") {
		t.Fatalf("迟到恢复应被记录为不可配对，实际 %v", eng2.UnmatchedResolves)
	}
	r2 := roles(round2)
	if r2["a-api-2"] != "suppressed_child" {
		t.Fatalf("重启后规则抑制仍应对第 2 轮生效: %v", r2)
	}

	if len(eng2.Alerts()) != 12 {
		t.Fatalf("原始告警应累计 12 条，实际 %d", len(eng2.Alerts()))
	}

	// 通知在重启后的新阶段只应为新事件补发，旧事件不重复通知。
	kinds2 := map[string]int{}
	for _, m := range sink2.Log() {
		kinds2[m.Kind]++
	}
	if kinds2["event_opened"] != 1 || kinds2["event_resolved"] != 1 || kinds2["child_suppressed"] != 1 {
		t.Fatalf("重启后通知计数错误: %v", kinds2)
	}
}

func TestNoMergeByMessageSimilarityAndNoDependentNoSuppress(t *testing.T) {
	base := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	alerts := []model.Alert{
		{ID: "x1", Service: "cache", Resource: "r1", Status: model.AlertFiring,
			StartsAt: base, ReceivedAt: base, Message: "db 连接超时"},
		{ID: "x2", Service: "db", Resource: "r9", Status: model.AlertFiring,
			StartsAt: base.Add(time.Minute), ReceivedAt: base.Add(time.Minute), Message: "db 连接超时"},
	}
	dir := filepath.Join(t.TempDir(), "data")
	sink := notify.NewRecordingSink()
	eng := engine.New(store.New(dir), sink)
	if err := eng.Load(); err != nil {
		t.Fatal(err)
	}
	if err := eng.PublishRules(scenario.Rules()); err != nil {
		t.Fatal(err)
	}
	ingest(t, eng, alerts)
	if got := len(eng.Events()); got != 2 {
		t.Fatalf("消息相同但服务不同、且无依赖证据，必须形成 2 个独立事件，实际 %d", got)
	}
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
