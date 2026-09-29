package scenario

import (
	"time"

	"alertcorr/internal/model"
)

const RuleVersion = "rules-2026-09-29.v1"

func at(min int) time.Time {
	t, _ := time.Parse(time.RFC3339, "2026-09-29T10:00:00+08:00")
	return t.Add(time.Duration(min) * time.Minute)
}

// Rules 定义显式依赖：web 依赖 api，api 依赖 db。父故障可抑制子告警。
func Rules() model.RuleSet {
	return model.RuleSet{
		Version:     RuleVersion,
		Description: "web->api->db 显式依赖",
		ActivatedAt: at(-10),
		Deps: []model.Dep{
			{Parent: "db", Child: "api", Reason: "api 读写依赖 db 连接"},
			{Parent: "api", Child: "web", Reason: "web 通过 api 提供服务"},
		},
	}
}

// Phase1 第一轮故障：db 根因 + 子告警 + 重复告警 + 正常恢复。
func Phase1() []model.Alert {
	return []model.Alert{
		{ID: "a-db-1", Service: "db", Resource: "db-primary", Status: model.AlertFiring,
			StartsAt: at(0), ReceivedAt: at(0), Message: "连接池耗尽"},
		{ID: "a-api-1", Service: "api", Resource: "api-canary", Status: model.AlertFiring,
			StartsAt: at(1), ReceivedAt: at(1), Message: "上游 db 超时"},
		{ID: "a-db-1-dup", Service: "db", Resource: "db-primary", Status: model.AlertFiring,
			StartsAt: at(0), ReceivedAt: at(2), Message: "磁盘 IO 等待飙升（文本完全不同）"},
		{ID: "a-web-1", Service: "web", Resource: "web-edge", Status: model.AlertFiring,
			StartsAt: at(3), ReceivedAt: at(3), Message: "502 Bad Gateway"},
		{ID: "a-api-1-res", Service: "api", Resource: "api-canary", Status: model.AlertResolved,
			StartsAt: at(1), EndsAt: at(10), ReceivedAt: at(10), Message: "恢复"},
		{ID: "a-web-1-res", Service: "web", Resource: "web-edge", Status: model.AlertResolved,
			StartsAt: at(3), EndsAt: at(11), ReceivedAt: at(11), Message: "恢复"},
		{ID: "a-db-1-res", Service: "db", Resource: "db-primary", Status: model.AlertResolved,
			StartsAt: at(0), EndsAt: at(12), ReceivedAt: at(12), Message: "连接池恢复"},
	}
}

// Phase2 重启后：db 再次发生，且上一轮迟到恢复到达，不得关闭新一轮事件。
func Phase2() []model.Alert {
	return []model.Alert{
		{ID: "a-db-2", Service: "db", Resource: "db-primary", Status: model.AlertFiring,
			StartsAt: at(20), ReceivedAt: at(20), Message: "主从复制中断"},
		{ID: "a-api-2", Service: "api", Resource: "api-canary", Status: model.AlertFiring,
			StartsAt: at(21), ReceivedAt: at(21), Message: "db 不可写"},
		// 迟到恢复：属于第 1 轮（StartsAt=10:00），却在第 2 轮开放时到达。
		{ID: "a-db-1-late-res", Service: "db", Resource: "db-primary", Status: model.AlertResolved,
			StartsAt: at(0), EndsAt: at(13), ReceivedAt: at(25), Message: "迟到的恢复通知"},
		{ID: "a-db-2-res", Service: "db", Resource: "db-primary", Status: model.AlertResolved,
			StartsAt: at(20), EndsAt: at(30), ReceivedAt: at(30), Message: "复制恢复"},
		{ID: "a-api-2-res", Service: "api", Resource: "api-canary", Status: model.AlertResolved,
			StartsAt: at(21), EndsAt: at(31), ReceivedAt: at(31), Message: "恢复"},
	}
}
