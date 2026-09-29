package model

import "time"

// AlertStatus 是原始告警的生命周期状态。
type AlertStatus string

const (
	AlertFiring   AlertStatus = "firing"
	AlertResolved AlertStatus = "resolved"
)

// Alert 是原始告警。原始告警一经接收即原样持久化，不做就地修改。
type Alert struct {
	ID         string            `json:"id"`
	Service    string            `json:"service"`
	Resource   string            `json:"resource"`
	Status     AlertStatus       `json:"status"`
	StartsAt   time.Time         `json:"startsAt"`
	EndsAt     time.Time         `json:"ends_at,omitempty"`
	Message    string            `json:"message"`
	Labels     map[string]string `json:"labels,omitempty"`
	ReceivedAt time.Time         `json:"received_at"`
}

// Fingerprint 标识同一故障根因的同一轮触发。
// 仅基于规则身份 + 服务 + 资源 + 本轮 StartsAt，不使用消息文本相似度。
func (a Alert) Fingerprint() string {
	return a.Service + "|" + a.Resource + "|" + a.StartsAt.UTC().Format(time.RFC3339Nano)
}

// Dep 是一条显式服务依赖边：Child 依赖 Parent（Parent 故障会抑制 Child 的告警）。
type Dep struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Reason string `json:"reason"`
}

// RuleSet 是一个版本化的规则集合：包含去重身份规则与显式依赖证据。
type RuleSet struct {
	Version     string    `json:"version"`
	Description string    `json:"description"`
	Deps        []Dep     `json:"deps"`
	ActivatedAt time.Time `json:"activated_at"`
}

// EventStatus 是关联事件的生命周期状态。
type EventStatus string

const (
	EventOpen     EventStatus = "open"
	EventResolved EventStatus = "resolved"
)

// Suppression 记录一条“父故障抑制子告警”的证据链。
type Suppression struct {
	ChildService  string    `json:"child_service"`
	ChildAlertID  string    `json:"child_alert_id"`
	ParentService string    `json:"parent_service"`
	ParentEventID string    `json:"parent_event_id"`
	RuleVersion   string    `json:"rule_version"`
	Reason        string    `json:"reason"`
	SuppressedAt  time.Time `json:"suppressed_at"`
}

// Source 记录被并入某个事件的一条原始告警来源。
type Source struct {
	AlertID  string      `json:"alert_id"`
	Service  string      `json:"service"`
	Resource string      `json:"resource"`
	Status   AlertStatus `json:"status"`
	Role     string      `json:"role"` // "root" | "duplicate" | "suppressed_child"
	At       time.Time   `json:"at"`
}

// Event 是关联后的事件身份，独立于原始告警持久化。
type Event struct {
	ID           string      `json:"id"`
	Fingerprint  string      `json:"fingerprint"`
	RootService  string      `json:"root_service"`
	RootResource string      `json:"root_resource"`
	Status       EventStatus `json:"status"`
	OpenedAt     time.Time   `json:"opened_at"`
	ResolvedAt   time.Time   `json:"resolved_at,omitempty"`
	// TriggerStartsAt 是本轮故障的 StartsAt，用于与恢复配对，
	// 防止上一轮迟到的 resolved 关闭新一轮 firing 的事件。
	TriggerStartsAt time.Time     `json:"trigger_starts_at"`
	LastUpdateAt    time.Time     `json:"last_update_at"`
	RuleVersion     string        `json:"rule_version"`
	Title           string        `json:"title"`
	Sources         []Source      `json:"sources"`
	Suppressions    []Suppression `json:"suppressions"`
}

// HasSource 报告该事件是否已收录某条原始告警。
func (e *Event) HasSource(alertID string) bool {
	for _, s := range e.Sources {
		if s.AlertID == alertID {
			return true
		}
	}
	return false
}
