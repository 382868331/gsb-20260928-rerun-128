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
func (e *Engine) Process(a model.Alert) (Result, error) {
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
		parent.SuppressedAlertIDs = append(parent.SuppressedAlertIDs, a.ID)
		sup := model.Suppression{
			AlertID:          a.ID,
			ChildSource:      a.Source,
			ParentIncidentID: parent.ID,
			ParentSource:     parent.Source,
			CreatedAt:        e.now(),
		}
		if err := e.store.AppendSuppression(sup); err != nil {
			return Result{}, err
		}
		if err := e.store.SaveIncidents(); err != nil {
			return Result{}, err
		}
		_ = e.notifier.Notify(notify.Event{Kind: "alert_suppressed", IncidentID: parent.ID,
			Detail: fmt.Sprintf("alert %s from %s suppressed by %s", a.ID, a.Source, parent.Source),
			At:     e.now()})
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
	_ = e.notifier.Notify(notify.Event{Kind: "incident_opened", IncidentID: inc.ID,
		Detail: fmt.Sprintf("%s epoch %d", a.Fingerprint, a.Epoch), At: e.now()})
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
	_ = e.notifier.Notify(notify.Event{Kind: "incident_resolved", IncidentID: inc.ID,
		Detail: fmt.Sprintf("resolved at epoch %d", a.Epoch), At: e.now()})
	return Result{OutcomeResolved, inc.ID}, nil
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
