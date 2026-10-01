// Package correlator 实现告警关联引擎：
// 同一故障的重复告警归并为一个事件，处理恢复与再次发生，
// 父故障在有显式依赖证据时抑制子告警。绝不按消息相似度合并。
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
	seq      int
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
	OutcomeDuplicate       Outcome = "duplicate"        // 重放的已处理告警，直接跳过
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
// 同一 ID 的告警重复重放时直接跳过，不产生任何副作用或额外通知。
func (e *Engine) Process(a model.Alert) (Result, error) {
	if a.ReceivedAt.IsZero() {
		a.ReceivedAt = e.now()
	}
	if a.Fingerprint == "" {
		a.Fingerprint = a.Source + "/" + a.Check
	}
	if a.ID != "" && e.store.HasAlert(a.ID) {
		return Result{Outcome: OutcomeDuplicate}, nil
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
		e.emit("incident_resolved", inc.ID, "superseded by new epoch")
	}

	// 父故障抑制：需要显式依赖证据（告警声明 DependsOn 且规则依赖图确认），
	// 仅凭消息相似一律不合并、不抑制。
	if parent := e.parentByEvidence(a); parent != nil {
		if sup := e.store.FindSuppression(a.ID); sup != nil && sup.Status == model.SuppressionActive {
			// 已有活动抑制记录（例如重启后重放）：不重复记录、不重复通知。
			return Result{OutcomeSuppressed, parent.ID}, nil
		}
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
			return Result{}, err
		}
		if err := e.store.SaveIncidents(); err != nil {
			return Result{}, err
		}
		e.emit("alert_suppressed", parent.ID,
			fmt.Sprintf("alert %s from %s suppressed by %s", a.ID, a.Source, parent.Source))
		return Result{OutcomeSuppressed, parent.ID}, nil
	}

	e.seq++
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
		return Result{}, err
	}
	e.emit("incident_opened", inc.ID, fmt.Sprintf("%s epoch %d", a.Fingerprint, a.Epoch))
	// 父告警可能迟到：吸收此前已开立、且带有效依赖证据的子事件。
	if err := e.absorbLateChildren(inc); err != nil {
		return Result{}, err
	}
	return Result{OutcomeOpened, inc.ID}, nil
}

func (e *Engine) processResolved(a model.Alert) (Result, error) {
	inc := e.store.ActiveIncident(a.Fingerprint)
	if inc == nil {
		return Result{Outcome: OutcomeUnmatched}, nil
	}
	if a.Epoch < inc.Epoch {
		// 迟到恢复：属于上一轮，不能关闭新一轮事件。
		return Result{OutcomeStaleRecovery, inc.ID}, nil
	}
	inc.Status = model.IncidentResolved
	inc.ResolvedAt = a.StartsAt
	if err := e.store.SaveIncidents(); err != nil {
		return Result{}, err
	}
	e.emit("incident_resolved", inc.ID, fmt.Sprintf("resolved at epoch %d", a.Epoch))
	return Result{OutcomeResolved, inc.ID}, nil
}

// emit 把通知写入本地记录（按 DedupKey 去重），仅新增时才交给 Notifier。
func (e *Engine) emit(kind, incidentID, detail string) {
	n := model.Notification{
		Kind:       kind,
		IncidentID: incidentID,
		Detail:     detail,
		DedupKey:   kind + "|" + incidentID + "|" + detail,
		At:         e.now(),
	}
	added, err := e.store.AppendNotification(n)
	if err != nil || !added {
		return
	}
	_ = e.notifier.Notify(notify.Event{Kind: kind, IncidentID: incidentID, Detail: detail, At: n.At})
}

// absorbLateChildren 父事件开立后，把已活动、声明依赖该父源且规则图确认
// 的子事件转为被抑制状态，其告警并入父事件的抑制清单。
func (e *Engine) absorbLateChildren(parent *model.Incident) error {
	for _, child := range e.store.Incidents {
		if child.Status != model.IncidentActive || child.ID == parent.ID {
			continue
		}
		if !e.edgeConfirmed(parent.Source, child.Source) || !e.declaresDependency(child, parent.Source) {
			continue
		}
		child.Status = model.IncidentSuppressed
		child.ResolvedAt = e.now()
		parent.SuppressedAlertIDs = append(parent.SuppressedAlertIDs, child.AlertIDs...)
		for _, alertID := range child.AlertIDs {
			if err := e.store.AppendSuppression(model.Suppression{
				AlertID:          alertID,
				ChildSource:      child.Source,
				ParentIncidentID: parent.ID,
				ParentSource:     parent.Source,
				RuleVersion:      e.store.Rules.Version,
				Status:           model.SuppressionActive,
				CreatedAt:        e.now(),
			}); err != nil {
				return err
			}
		}
		e.emit("alert_suppressed", parent.ID,
			fmt.Sprintf("late parent %s absorbed child incident %s", parent.Source, child.ID))
	}
	return e.store.SaveIncidents()
}

func (e *Engine) declaresDependency(inc *model.Incident, parentSource string) bool {
	for _, id := range inc.AlertIDs {
		if a := e.store.FindAlert(id); a != nil {
			for _, dep := range a.DependsOn {
				if dep == parentSource {
					return true
				}
			}
		}
	}
	return false
}

// ApplyRules 应用新规则集并审查既有抑制：依赖边被撤回的抑制解除，
// 仍在图中的保持；每条抑制都保留当初判断所用的规则版本。
// 返回人可读的审查报告。
func (e *Engine) ApplyRules(r model.RuleSet) ([]string, error) {
	if err := e.store.SaveRules(r); err != nil {
		return nil, err
	}
	var report []string
	for i := range e.store.Suppressions {
		sup := &e.store.Suppressions[i]
		if sup.Status != model.SuppressionActive && sup.Status != model.SuppressionLifted {
			continue
		}
		if e.edgeConfirmed(sup.ParentSource, sup.ChildSource) {
			report = append(report, fmt.Sprintf("保持抑制 %s：边 %s->%s 仍在 %s（原判定用 %s）",
				sup.AlertID, sup.ParentSource, sup.ChildSource, r.Version, sup.RuleVersion))
			continue
		}
		sup.Status = model.SuppressionReleased
		sup.EndedAt = e.now()
		e.emit("suppression_released", sup.ParentIncidentID,
			fmt.Sprintf("suppression of %s released: edge %s->%s removed in %s (judged with %s)",
				sup.AlertID, sup.ParentSource, sup.ChildSource, r.Version, sup.RuleVersion))
		report = append(report, fmt.Sprintf("解除抑制 %s：边 %s->%s 在 %s 中撤回（原判定用 %s）",
			sup.AlertID, sup.ParentSource, sup.ChildSource, r.Version, sup.RuleVersion))
	}
	return report, e.store.SaveSuppressions()
}

// Evidence 是分析人员解除抑制时看到的判断证据。
type Evidence struct {
	Suppression        model.Suppression
	ParentIncidentID   string
	ParentActive       bool
	EdgeConfirmed      bool   // 当前规则图是否仍确认该依赖边
	JudgedRuleVersion  string // 当初做出抑制判断的规则版本
	CurrentRuleVersion string
}

// LiftSuppression 暂时解除一条抑制并返回其证据；操作结束后应调用
// Reevaluate 按当前状态重新判断。
func (e *Engine) LiftSuppression(alertID string) (*Evidence, error) {
	sup := e.store.FindSuppression(alertID)
	if sup == nil || sup.Status != model.SuppressionActive {
		return nil, fmt.Errorf("no active suppression for alert %s", alertID)
	}
	sup.Status = model.SuppressionLifted
	if err := e.store.SaveSuppressions(); err != nil {
		return nil, err
	}
	e.emit("suppression_lifted", sup.ParentIncidentID, "analyst lifted suppression of "+alertID)
	return e.evidenceFor(sup), nil
}

func (e *Engine) evidenceFor(sup *model.Suppression) *Evidence {
	return &Evidence{
		Suppression:        *sup,
		ParentIncidentID:   sup.ParentIncidentID,
		ParentActive:       e.store.ActiveIncidentBySource(sup.ParentSource) != nil,
		EdgeConfirmed:      e.edgeConfirmed(sup.ParentSource, sup.ChildSource),
		JudgedRuleVersion:  sup.RuleVersion,
		CurrentRuleVersion: e.store.Rules.Version,
	}
}

// Reevaluate 分析操作结束后，按当前规则图与父事件状态重新判断所有
// 被暂时解除的抑制：证据仍成立则恢复抑制，否则正式解除。
func (e *Engine) Reevaluate() ([]string, error) {
	var report []string
	for i := range e.store.Suppressions {
		sup := &e.store.Suppressions[i]
		if sup.Status != model.SuppressionLifted {
			continue
		}
		if e.edgeConfirmed(sup.ParentSource, sup.ChildSource) &&
			e.store.ActiveIncidentBySource(sup.ParentSource) != nil {
			sup.Status = model.SuppressionActive
			e.emit("suppression_reinstated", sup.ParentIncidentID,
				"suppression of "+sup.AlertID+" reinstated after review")
			report = append(report, "恢复抑制 "+sup.AlertID)
			continue
		}
		sup.Status = model.SuppressionReleased
		sup.EndedAt = e.now()
		e.emit("suppression_released", sup.ParentIncidentID,
			"suppression of "+sup.AlertID+" released after review")
		report = append(report, "解除抑制 "+sup.AlertID)
	}
	return report, e.store.SaveSuppressions()
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
	for _, edge := range e.store.Rules.Dependencies {
		if edge.Parent == parent && edge.Child == child {
			return true
		}
	}
	return false
}
