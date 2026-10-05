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
	Kind        string    `json:"kind"`
	IncidentID  string    `json:"incident_id"`
	Detail      string    `json:"detail"`
	DedupKey    string    `json:"dedup_key"`
	Basis       []Basis   `json:"basis,omitempty"`       // 发出该通知时生效的解释依据（快照，事后不改写）
	SubjectID   string    `json:"subject_id,omitempty"`  // 生命周期统一主体：子事件 ID（抑制/原因撤回/恢复一致）
	AlertID     string    `json:"alert_id,omitempty"`    // 触发该通知的原始告警 ID（可查询关联，不作为主体）
	Fingerprint string    `json:"fingerprint,omitempty"` // 子告警稳定指纹（可查询关联，不作为主体）
	At          time.Time `json:"at"`
}

// Basis 是一条通知做出时所依据的单条原因解释的快照。
// 通知一旦发出，其依据原样保留，后续原因补到/撤回/收窄都不改写历史。
type Basis struct {
	ExplanationID    string `json:"explanation_id"`
	AlertID          string `json:"alert_id"`
	ParentSource     string `json:"parent_source"`
	ParentIncidentID string `json:"parent_incident_id"`
	State            string `json:"state"`
	RuleVersion      string `json:"rule_version"`
}

// Explanation 是针对某个子告警身份（fingerprint）的一条原因解释。
// 同一个告警可同时挂多条相互独立的解释；只要还有一条活动的 confirmed
// 解释，该告警就继续被抑制，单个父事件恢复不会让它重新通知。
type Explanation struct {
	ID               string        `json:"id"`
	AlertFingerprint string        `json:"alert_fingerprint"`
	SubjectID        string        `json:"subject_id"` // 该解释影响的通知主体（统一为子事件 ID）
	AlertIDs         []string      `json:"alert_ids"`  // 支撑该解释的原始观察（重复观察不重复计原因）
	ChildSource      string        `json:"child_source"`
	ParentSource     string        `json:"parent_source"`
	ParentIncidentID string        `json:"parent_incident_id"`
	State            string        `json:"state"`        // confirmed | suspected | withdrawn
	Basis            string        `json:"basis"`        // declared_evidence | suspected_candidate
	RuleVersion      string        `json:"rule_version"` // 做出判断时的规则版本
	Scope            []string      `json:"scope"`        // 关联范围（命中的具体告警 ID），可被收窄
	CreatedAt        time.Time     `json:"created_at"`
	History          []StateChange `json:"history"`
	EndedAt          time.Time     `json:"ended_at,omitempty"`
	EndReason        string        `json:"end_reason,omitempty"` // parent_resolved | edge_withdrawn | operator_removed | superseded
}

// StateChange 记录解释状态机上的每次变迁，保证当前状态与历史解释都可追溯。
type StateChange struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	Reason      string    `json:"reason"`
	Detail      string    `json:"detail,omitempty"`
	RuleVersion string    `json:"rule_version,omitempty"`
	At          time.Time `json:"at"`
}

const (
	ExplConfirmed = "confirmed" // 已确认：告警自带依赖证据且规则图确认该边
	ExplSuspected = "suspected" // 待核实：活动父事件+规则图命中，但尚无显式依赖证据
	ExplWithdrawn = "withdrawn" // 被撤回：父恢复/边撤回/操作者移除/被更具体解释取代
)

const (
	EndParentResolved  = "parent_resolved"
	EndEdgeWithdrawn   = "edge_withdrawn"
	EndOperatorRemoved = "operator_removed"
	EndSuperseded      = "superseded"
)

const (
	BasisDeclared  = "declared_evidence"
	BasisSuspected = "suspected_candidate"
)

// Active 表示该解释当前仍在影响通知决定。
func (x *Explanation) Active() bool {
	return x.State == ExplConfirmed || x.State == ExplSuspected
}

// SetState 记录一次状态变迁并更新当前状态；历史永不被覆盖。
func (x *Explanation) SetState(to, reason, detail, ruleVersion string, at time.Time) {
	change := StateChange{From: x.State, To: to, Reason: reason, Detail: detail,
		RuleVersion: ruleVersion, At: at}
	x.History = append(x.History, change)
	x.State = to
	if to == ExplWithdrawn {
		x.EndedAt = at
		x.EndReason = reason
	}
}

// RecordScope 在历史中追加一条范围变更记录，但不改变当前状态。
func (x *Explanation) RecordScope(reason, detail, ruleVersion string, at time.Time) {
	x.History = append(x.History, StateChange{From: x.State, To: x.State,
		Reason: reason, Detail: detail, RuleVersion: ruleVersion, At: at})
}

// DecisionState 持久化每个子告警身份当前的通知决定，
// 保证“最后一条原因消失时才重新通知”且重复重放不重发。
type DecisionState struct {
	Fingerprint string `json:"fingerprint"`
	SubjectID   string `json:"subject_id"`         // 被抑制的子事件 ID（生命周期统一主体）
	Session     string `json:"session"`            // 当前抑制轮次（活动 confirmed 父事件集合）
	Resumed     bool   `json:"resumed"`            // 本轮是否已发出恢复通知，防重发
	Observed    bool   `json:"observed,omitempty"` // 是否已对该主体做出过通知决定
}
