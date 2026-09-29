package main

import (
	"flag"
	"fmt"
	"os"

	"alertcorr/internal/engine"
	"alertcorr/internal/model"
	"alertcorr/internal/notify"
	"alertcorr/internal/scenario"
	"alertcorr/internal/store"
)

func printEvents(events []*model.Event, unmatched []string) {
	for _, ev := range events {
		state := string(ev.Status)
		end := "-"
		if !ev.ResolvedAt.IsZero() {
			end = ev.ResolvedAt.Format("15:04")
		}
		fmt.Printf("  事件 %s  %s/%s  %s  开始=%s 结束=%s  来源=%d 抑制=%d\n",
			ev.ID[:12], ev.RootService, ev.RootResource, state,
			ev.OpenedAt.Format("15:04"), end, len(ev.Sources), len(ev.Suppressions))
		for _, s := range ev.Sources {
			fmt.Printf("    - [%s] %s (%s)\n", s.Role, s.AlertID, s.Status)
		}
		for _, sup := range ev.Suppressions {
			fmt.Printf("    - 抑制 %s <- %s 证据: %s\n", sup.ParentService, sup.ChildService, sup.Reason)
		}
	}
	if len(unmatched) > 0 {
		fmt.Printf("  未配对/忽略的恢复告警: %v\n", unmatched)
	}
}

func run(dataDir string) error {
	sink := notify.NewRecordingSink()
	eng := engine.New(store.New(dataDir), sink)
	if err := eng.Load(); err != nil {
		return err
	}
	if eng.ActiveRules() == nil {
		if err := eng.PublishRules(scenario.Rules()); err != nil {
			return err
		}
		fmt.Printf("发布规则版本 %s\n", scenario.RuleVersion)
	}

	ingest := func(phase string, alerts []model.Alert) {
		fmt.Printf("\n=== %s（规则版本 %s）===\n", phase, eng.ActiveRules().Version)
		for _, a := range alerts {
			if err := eng.Ingest(a); err != nil {
				fmt.Fprintf(os.Stderr, "摄入失败 %s: %v\n", a.ID, err)
				os.Exit(1)
			}
			fmt.Printf("摄入 %-18s %-9s %s/%s\n", a.ID, a.Status, a.Service, a.Resource)
		}
		fmt.Println("当前事件：")
		printEvents(eng.Events(), eng.UnmatchedResolves)
	}

	ingest("阶段1：db 根因故障 + 子告警 + 重复 + 恢复", scenario.Phase1())

	// 模拟进程重启：新建引擎并从磁盘加载，抑制关系必须保留。
	fmt.Println("\n=== 模拟进程重启，从磁盘重新加载 ===")
	sink = notify.NewRecordingSink()
	eng = engine.New(store.New(dataDir), sink)
	if err := eng.Load(); err != nil {
		return err
	}
	fmt.Printf("重载完成：事件 %d 个，规则版本 %s\n", len(eng.Events()), eng.ActiveRules().Version)

	ingest("阶段2：再次发生 + 迟到恢复", scenario.Phase2())

	fmt.Println("\n=== 通知录制（不真实发送）===")
	for _, m := range sink.Log() {
		fmt.Printf("  [%s] %s: %s\n", m.Kind, m.EventID[:12], m.Text)
	}
	return nil
}

func main() {
	dataDir := flag.String("data", "data", "持久化目录（规则版本/原始告警/事件身份分别保存）")
	flag.Parse()
	if err := run(*dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}
