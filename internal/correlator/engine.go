// Package correlator 实现告警关联引擎：
// 同一故障的重复告警归并为一个事件，处理恢复与再次发生，
// 父故障在有显式依赖证据时抑制子告警。绝不按消息相似度合并。
// 依赖图变更后提供影响审查：已活动抑制按新图重新判断，
// 并永久保留原判断所用的规则版本。
package correlator

import (
	"fmt"
	"time"

	"alertcorr/internal/model"
	"alertcorr/internal/notify"
	"alertcorr/internal/store"
)

type Engine struct {
	store    *store.Store
	notifier notify.Notifier
	now      func() time.Time
}

type Outcome string

const (
	OutcomeOpened          Outcome = "opened"           // 新事件
	OutcomeMerged          Outcome = "merged"           // 重复告警并入已有事件
	OutcomeResolved        Outcome = "resolved"         // 恢复关闭事件
	OutcomeStaleRecovery   Outcome = "stale_recovery"   // 迟到恢复，不影响新一轮事件
	OutcomeUnmatched       Outcome = "unmatched"        // 无匹配事件的恢复
	OutcomeSuppressed      Outcome = "suppressed"       // 被父故障抑制
	OutcomeAlreadyResolved Outcome = "already_resolved" // 重复恢复
	OutcomeReplayed        Outcome = "replayed"         // 重复重放，无副作用
)

type Result struct {
	Outcome    Outcome
	IncidentID string
}

func New(st *store.Store, n notify.Notifier) *Engine {
	return &Engine{store: st, notifier: n, now: time.Now}
}

// SetClock 便于测试与内置序列注入确定时间。
func (e *Engine) SetClock(now func() time.Time) { e.now = now }

func (e *Engine) Store() *store.Store { return e.store }

// Process 处理一条原始告警：先原样落库，再按当前规则版本关联。
// 同一告警 ID 重复重放时直接返回 replayed，不产生副作用与重复通知。
func (e *Engine) Process(a model.Alert) (Result, error) {
	if a.ID != "" && e.store.FindAlert(a.ID) != nil {
		return Result{Outcome: OutcomeReplayed}, nil
	}
	if a.ReceivedAt.IsZero() {
		a.ReceivedAt = e.now()
	}
	if a.Fingerprint == "" {
		a.Fingerprint = a.Source + "/" + a.Check
	}
	if err := e.store.AppendAlert(a); err != nil {
		return Result{}, err
	}

	if a.Status == model.StatusResolved {
		return e.processResolved(a)
	}
	return e.processFiring(a)
}

func (e *Engine) processFiring(a model.Alert) (Result, error) {
	if inc := e.store.ActiveIncident(a.Fingerprint); inc != nil {
		if a.Epoch <= inc.Epoch {
			// 同一轮故障的重复告警：合并。
			inc.AlertIDs = append(inc.AlertIDs, a.ID)
			return Result{OutcomeMerged, inc.ID}, e.store.SaveIncidents()
		}
		// 来源未走恢复就直接新一轮：旧事件按新轮次更替前先关闭。
		inc.Status = model.IncidentResolved
		inc.ResolvedAt = a.StartsAt
		_ = e.notifier.Notify(notify.Event{Kind: "incident_resolved", IncidentID: inc.ID,
			Detail: "superseded by new epoch", At: e.now()})
	}

	// 父故障抑制：需要显式依赖证据（告警声明 DependsOn 且规则依赖图确认），
	// 仅凭消息相似一律不合并、不抑制。
	if parent := e.parentByEvidence(a); parent != nil {
		if err := e.suppress(a, parent); err != nil {
			return Result{}, err
		}
		return Result{OutcomeSuppressed, parent.ID}, nil
	}

	inc, err := e.openIncident(a)
	if err != nil {
		return Result{}, err
	}
	// 父告警可能迟到：它开火时，此前因父事件未活动而独立成事件的
	// 子告警应按依赖证据改判为抑制。
	if err := e.adoptLateChildren(inc); err != nil {
		return Result{}, err
	}
	return Result{OutcomeOpened, inc.ID}, nil
}

func (e *Engine) openIncident(a model.Alert) (*model.Incident, error) {
	inc := &model.Incident{
		ID:          fmt.Sprintf("inc-%s-%d", a.Fingerprint, a.Epoch),
		Fingerprint: a.Fingerprint,
		Source:      a.Source,
		Check:       a.Check,
		Epoch:       a.Epoch,
		Status:      model.IncidentActive,
		Severity:    a.Severity,
		StartedAt:   a.StartsAt,
		AlertIDs:    []string{a.ID},
		RuleVersion: e.store.Rules.Version,
	}
	e.store.Incidents = append(e.store.Incidents, inc)
	if err := e.store.SaveIncidents(); err != nil {
		return nil, err
	}
	_ = e.notifier.Notify(notify.Event{Kind: "incident_opened", IncidentID: inc.ID,
		Detail: fmt.Sprintf("%s epoch %d", a.Fingerprint, a.Epoch), At: e.now()})
	return inc, nil
}

// suppress 把子告警挂到父事件下，抑制记录带当前规则版本。
func (e *Engine) suppress(a model.Alert, parent *model.Incident) error {
	parent.SuppressedAlertIDs = append(parent.SuppressedAlertIDs, a.ID)
	sup := model.Suppression{
		AlertID:          a.ID,
		ChildSource:      a.Source,
		ParentIncidentID: parent.ID,
		ParentSource:     parent.Source,
		RuleVersion:      e.store.Rules.Version,
		Status:           model.SuppressionActive,
		CreatedAt:        e.now(),
	}
	if err := e.store.AppendSuppression(sup); err != nil {
		return err
	}
	if err := e.store.SaveIncidents(); err != nil {
		return err
	}
	_ = e.notifier.Notify(notify.Event{Kind: "alert_suppressed", IncidentID: parent.ID,
		Detail: fmt.Sprintf("alert %s from %s suppressed by %s", a.ID, a.Source, parent.Source),
		At:     e.now()})
	return nil
}

// adoptLateChildren 父事件（可能迟到）开火后，把已独立成事件、但带有
// 指向该父的依赖证据的子事件改判为抑制。
func (e *Engine) adoptLateChildren(parent *model.Incident) error {
	for _, child := range e.store.Incidents {
		if child.Status != model.IncidentActive || child.ID == parent.ID {
			continue
		}
		if len(child.AlertIDs) == 0 {
			continue
		}
		first := e.store.FindAlert(child.AlertIDs[0])
		if first == nil || !contains(first.DependsOn, parent.Source) ||
			!e.edgeConfirmed(parent.Source, child.Source) {
			continue
		}
		child.Status = model.IncidentResolved
		child.ResolvedAt = e.now()
		for _, id := range child.AlertIDs {
			a := e.store.FindAlert(id)
			if a == nil {
				continue
			}
			if err := e.suppress(*a, parent); err != nil {
				return err
			}
		}
		_ = e.notifier.Notify(notify.Event{Kind: "incident_resolved", IncidentID: child.ID,
			Detail: "reclassified as suppressed by late parent " + parent.ID, At: e.now()})
	}
	return e.store.SaveIncidents()
}

func (e *Engine) processResolved(a model.Alert) (Result, error) {
	inc := e.store.ActiveIncident(a.Fingerprint)
	if inc == nil {
		return Result{Outcome: OutcomeUnmatched}, nil
	}
	if a.Epoch < inc.Epoch {
		// 迟到恢复：属于上一轮，不能关闭新一轮事件，
		// 旧轮次的恢复通知也绝不套到重新发生的故障上。
		return Result{OutcomeStaleRecovery, inc.ID}, nil
	}
	inc.Status = model.IncidentResolved
	inc.ResolvedAt = a.StartsAt
	if err := e.store.SaveIncidents(); err != nil {
		return Result{}, err
	}
	_ = e.notifier.Notify(notify.Event{Kind: "incident_resolved", IncidentID: inc.ID,
		Detail: fmt.Sprintf("resolved at epoch %d", a.Epoch), At: e.now()})
	return Result{OutcomeResolved, inc.ID}, nil
}

// ReviewRules 应用新规则集并做影响审查：逐条核对已活动抑制所依赖的边
// 是否仍在新依赖图中；被撤销的边对应抑制解除，子告警重新立为活动事件。
// 原抑制记录与其判断所用规则版本永久保留，审查过程写入审计记录。
func (e *Engine) ReviewRules(newRules model.RuleSet) error {
	old := e.store.Rules
	for _, edge := range old.Dependencies {
		if !edgeIn(newRules, edge) {
			_ = e.store.AppendReview(model.ReviewEntry{At: e.now(), Action: "edge_removed",
				Detail:      fmt.Sprintf("%s -> %s removed in %s", edge.Parent, edge.Child, newRules.Version),
				RuleVersion: newRules.Version})
		}
	}
	for _, edge := range newRules.Dependencies {
		if !edgeIn(old, edge) {
			_ = e.store.AppendReview(model.ReviewEntry{At: e.now(), Action: "edge_added",
				Detail:      fmt.Sprintf("%s -> %s added in %s", edge.Parent, edge.Child, newRules.Version),
				RuleVersion: newRules.Version})
		}
	}
	if err := e.store.SaveRules(newRules); err != nil {
		return err
	}
	for i := range e.store.Suppressions {
		sup := &e.store.Suppressions[i]
		if sup.Status != model.SuppressionActive {
			continue
		}
		if !e.parentActive(sup.ParentIncidentID) {
			continue // 父事件已结束，历史抑制不再变更
		}
		if e.edgeConfirmed(sup.ParentSource, sup.ChildSource) {
			continue // 边仍在，抑制继续生效
		}
		if err := e.release(sup, "dependency edge removed in "+newRules.Version); err != nil {
			return err
		}
	}
	return e.store.SaveSuppressions()
}

func (e *Engine) parentActive(incidentID string) bool {
	for _, inc := range e.store.Incidents {
		if inc.ID == incidentID {
			return inc.Status == model.IncidentActive
		}
	}
	return false
}

// release 解除一条抑制：若子告警没有活动事件则重新开立，并通知、审计。
func (e *Engine) release(sup *model.Suppression, reason string) error {
	sup.Status = model.SuppressionReleased
	sup.Reason = reason
	sup.UpdatedAt = e.now()
	_ = e.store.AppendReview(model.ReviewEntry{At: e.now(), Action: "release",
		AlertID: sup.AlertID, Detail: reason, RuleVersion: e.store.Rules.Version})
	_ = e.notifier.Notify(notify.Event{Kind: "suppression_released",
		IncidentID: sup.ParentIncidentID,
		Detail:     fmt.Sprintf("alert %s released: %s", sup.AlertID, reason), At: e.now()})
	a := e.store.FindAlert(sup.AlertID)
	if a == nil {
		return nil
	}
	if e.store.ActiveIncident(a.Fingerprint) == nil {
		if _, err := e.openIncident(*a); err != nil {
			return err
		}
	}
	return nil
}

// Evidence 是一条抑制的判断证据，供分析人员查看。
type Evidence struct {
	Suppression   model.Suppression
	Alert         *model.Alert
	Parent        *model.Incident
	EdgeConfirmed bool   // 当前规则图是否仍确认该依赖边
	RuleVersion   string // 原判断所用规则版本
}

// Evidence 查看一条抑制的证据，不改变其状态。
func (e *Engine) Evidence(alertID string) (*Evidence, error) {
	sup := e.store.FindSuppression(alertID)
	if sup == nil {
		return nil, fmt.Errorf("no suppression for alert %s", alertID)
	}
	ev := &Evidence{
		Suppression:   *sup,
		Alert:         e.store.FindAlert(alertID),
		EdgeConfirmed: e.edgeConfirmed(sup.ParentSource, sup.ChildSource),
		RuleVersion:   sup.RuleVersion,
	}
	for _, inc := range e.store.Incidents {
		if inc.ID == sup.ParentIncidentID {
			ev.Parent = inc
		}
	}
	return ev, nil
}

// LiftSuppression 允许分析人员暂时解除一条抑制并查看其证据；
// 解除后子告警立为活动事件，操作结束后应调用 RejudgeSuppression 重判。
func (e *Engine) LiftSuppression(alertID string) (*Evidence, error) {
	sup := e.store.FindSuppression(alertID)
	if sup == nil {
		return nil, fmt.Errorf("no suppression for alert %s", alertID)
	}
	if sup.Status != model.SuppressionActive {
		return nil, fmt.Errorf("suppression for alert %s is %s, cannot lift", alertID, sup.Status)
	}
	sup.Status = model.SuppressionLifted
	sup.UpdatedAt = e.now()
	if err := e.store.SaveSuppressions(); err != nil {
		return nil, err
	}
	_ = e.store.AppendReview(model.ReviewEntry{At: e.now(), Action: "lift",
		AlertID: alertID, Detail: "lifted by analyst", RuleVersion: e.store.Rules.Version})
	_ = e.notifier.Notify(notify.Event{Kind: "suppression_lifted",
		IncidentID: sup.ParentIncidentID,
		Detail:     fmt.Sprintf("alert %s lifted by analyst", alertID), At: e.now()})
	if a := e.store.FindAlert(alertID); a != nil && e.store.ActiveIncident(a.Fingerprint) == nil {
		if _, err := e.openIncident(*a); err != nil {
			return nil, err
		}
	}
	return e.Evidence(alertID)
}

// RejudgeSuppression 操作结束后按当前状态重新判断一条被解除的抑制：
// 依赖边仍确认且父事件仍活动则恢复抑制，否则正式解除。
func (e *Engine) RejudgeSuppression(alertID string) error {
	sup := e.store.FindSuppression(alertID)
	if sup == nil {
		return fmt.Errorf("no suppression for alert %s", alertID)
	}
	if sup.Status != model.SuppressionLifted {
		return fmt.Errorf("suppression for alert %s is %s, cannot rejudge", alertID, sup.Status)
	}
	parentActive := e.parentActive(sup.ParentIncidentID)
	_ = e.store.AppendReview(model.ReviewEntry{At: e.now(), Action: "rejudge",
		AlertID: alertID, RuleVersion: e.store.Rules.Version,
		Detail: fmt.Sprintf("edge_confirmed=%v parent_active=%v",
			e.edgeConfirmed(sup.ParentSource, sup.ChildSource), parentActive)})
	if e.edgeConfirmed(sup.ParentSource, sup.ChildSource) && parentActive {
		sup.Status = model.SuppressionActive
		sup.UpdatedAt = e.now()
		if a := e.store.FindAlert(alertID); a != nil {
			if inc := e.store.ActiveIncident(a.Fingerprint); inc != nil {
				inc.Status = model.IncidentResolved
				inc.ResolvedAt = e.now()
				_ = e.store.SaveIncidents()
			}
		}
		_ = e.notifier.Notify(notify.Event{Kind: "suppression_reinstated",
			IncidentID: sup.ParentIncidentID,
			Detail:     fmt.Sprintf("alert %s re-suppressed after rejudge", alertID), At: e.now()})
		return e.store.SaveSuppressions()
	}
	if err := e.release(sup, "no longer justified at rejudge"); err != nil {
		return err
	}
	return e.store.SaveSuppressions()
}

// parentByEvidence 仅当告警自带 DependsOn 声明、且规则依赖图确认该边时，
// 才返回处于活动状态的父事件；否则返回 nil。
func (e *Engine) parentByEvidence(a model.Alert) *model.Incident {
	for _, dep := range a.DependsOn {
		if !e.edgeConfirmed(dep, a.Source) {
			continue
		}
		if parent := e.store.ActiveIncidentBySource(dep); parent != nil {
			return parent
		}
	}
	return nil
}

func (e *Engine) edgeConfirmed(parent, child string) bool {
	return edgeIn(e.store.Rules, model.DependencyEdge{Parent: parent, Child: child})
}

func edgeIn(rules model.RuleSet, edge model.DependencyEdge) bool {
	for _, x := range rules.Dependencies {
		if x == edge {
			return true
		}
	}
	return false
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
