package model

import "time"

// Alert 是一条原始告警，原样保存，身份由 ID 标识。
type Alert struct {
	ID          string            `json:"id"`
	Fingerprint string            `json:"fingerprint"` // source+check 的稳定身份
	Source      string            `json:"source"`
	Check       string            `json:"check"`
	Severity    string            `json:"severity"`
	Status      string            `json:"status"` // firing | resolved
	Epoch       int               `json:"epoch"`  // 来源侧的发生轮次，恢复必须同轮次才生效
	Message     string            `json:"message"`
	DependsOn   []string          `json:"depends_on,omitempty"` // 显式依赖证据
	Labels      map[string]string `json:"labels,omitempty"`
	StartsAt    time.Time         `json:"starts_at"`
	ReceivedAt  time.Time         `json:"received_at"`
}

const (
	StatusFiring   = "firing"
	StatusResolved = "resolved"
)

// Incident 是一个事件，身份独立于原始告警保存。
type Incident struct {
	ID                 string    `json:"id"`
	Fingerprint        string    `json:"fingerprint"`
	Source             string    `json:"source"`
	Check              string    `json:"check"`
	Epoch              int       `json:"epoch"`
	Status             string    `json:"status"` // active | resolved
	Severity           string    `json:"severity"`
	StartedAt          time.Time `json:"started_at"`
	ResolvedAt         time.Time `json:"resolved_at,omitempty"`
	AlertIDs           []string  `json:"alert_ids"`            // 被合并的原始告警
	SuppressedAlertIDs []string  `json:"suppressed_alert_ids"` // 被抑制的子告警
	RuleVersion        string    `json:"rule_version"`
}

const (
	IncidentActive     = "active"
	IncidentResolved   = "resolved"
	IncidentSuppressed = "suppressed" // 父告警迟到后被吸收抑制
)

// RuleSet 是关联规则集，带版本号；每个事件记录处理它时所用的版本。
type RuleSet struct {
	Version      string           `json:"version"`
	Dependencies []DependencyEdge `json:"dependencies"`
}

// DependencyEdge 表示 Parent 故障会影响 Child。
type DependencyEdge struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
}

// Suppression 记录一条抑制关系，持久化后重启仍生效。
// RuleVersion 保留做出抑制判断时所用的规则版本，便于依赖图变更后审查。
type Suppression struct {
	AlertID          string    `json:"alert_id"`
	ChildSource      string    `json:"child_source"`
	ParentIncidentID string    `json:"parent_incident_id"`
	ParentSource     string    `json:"parent_source"`
	RuleVersion      string    `json:"rule_version"`
	Status           string    `json:"status"` // active | lifted | released
	CreatedAt        time.Time `json:"created_at"`
	EndedAt          time.Time `json:"ended_at,omitempty"`
}

const (
	SuppressionActive   = "active"
	SuppressionLifted   = "lifted"   // 分析人员暂时解除，待重新判断
	SuppressionReleased = "released" // 依赖边撤回或父事件结束，抑制解除
)

// Notification 是写入本地记录的通知，DedupKey 保证重复重放不产生多份。
type Notification struct {
	Kind       string    `json:"kind"`
	IncidentID string    `json:"incident_id"`
	Detail     string    `json:"detail"`
	DedupKey   string    `json:"dedup_key"`
	At         time.Time `json:"at"`
}
