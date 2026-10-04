// Package correlator 实现告警关联引擎：
// 同一故障的重复告警归并为一个事件，处理恢复与再次发生，
// 父故障在有显式依赖证据时抑制子告警。绝不按消息相似度合并。
package correlator

import (
	"fmt"
	"sort"
	"strings"
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
		if _, err := e.withdrawCauseForIncident(inc, "被新轮次事件更替"); err != nil {
			return Result{}, err
		}
	}

	// 父故障抑制：需要显式依赖证据（告警声明 DependsOn 且规则依赖图确认），
	// 仅凭消息相似一律不合并、不抑制。同一告警可同时归属多个独立原因。
	if parents := e.parentsByEvidence(a); len(parents) > 0 {
		var causeIDs, sources []string
		for _, parent := range parents {
			cause := e.store.FindCauseByIncident(parent.ID)
			if cause == nil {
				continue
			}
			causeIDs = append(causeIDs, cause.ID)
			if sup := e.store.FindSuppressionBy(a.ID, parent.ID); sup != nil &&
				sup.Status == model.SuppressionActive {
				// 已有活动抑制记录（例如重启后重放）：不重复记录。
				continue
			}
			parent.SuppressedAlertIDs = append(parent.SuppressedAlertIDs, a.ID)
			sup := model.Suppression{
				AlertID:          a.ID,
				ChildSource:      a.Source,
				ParentIncidentID: parent.ID,
				ParentSource:     parent.Source,
				CauseID:          cause.ID,
				RuleVersion:      e.store.Rules.Version,
				Status:           model.SuppressionActive,
				CreatedAt:        e.now(),
			}
			if err := e.store.AppendSuppression(sup); err != nil {
				return Result{}, err
			}
			sources = append(sources, parent.Source)
		}
		if err := e.store.SaveIncidents(); err != nil {
			return Result{}, err
		}
		if len(sources) > 0 {
			e.emit("alert_suppressed", parents[0].ID,
				fmt.Sprintf("alert %s from %s suppressed by %s", a.ID, a.Source, strings.Join(sources, ",")))
		}
		e.recordExplanation(a.ID, "suppressed", causeIDs,
			fmt.Sprintf("依赖证据+规则图确认，被 %d 个已确认原因覆盖", len(causeIDs)))
		return Result{OutcomeSuppressed, parents[0].ID}, nil
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
	e.recordExplanation(a.ID, "notify", nil, "无已确认原因覆盖，事件开立并及时通知")
	// 每个事件注册一个已确认原因；重复观察不会重复注册。
	if err := e.registerCauseForIncident(inc); err != nil {
		return Result{}, err
	}
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
	// 父事件恢复：撤回其原因，只重新评估受它影响的告警；
	// 仍有其他已确认原因的告警不重新通知。
	if _, err := e.withdrawCauseForIncident(inc,
		fmt.Sprintf("父事件于 epoch %d 恢复", a.Epoch)); err != nil {
		return Result{}, err
	}
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
		cause := e.store.FindCauseByIncident(parent.ID)
		causeID := ""
		if cause != nil {
			causeID = cause.ID
		}
		for _, alertID := range child.AlertIDs {
			if err := e.store.AppendSuppression(model.Suppression{
				AlertID:          alertID,
				ChildSource:      child.Source,
				ParentIncidentID: parent.ID,
				ParentSource:     parent.Source,
				CauseID:          causeID,
				RuleVersion:      e.store.Rules.Version,
				Status:           model.SuppressionActive,
				CreatedAt:        e.now(),
			}); err != nil {
				return err
			}
			e.recordExplanation(alertID, "suppressed", []string{causeID},
				"迟到父事件吸收，原因后来补到")
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
		// 关联范围收窄：在原因历史中留下可追溯记录。
		if c := e.store.FindCause(sup.CauseID); c != nil {
			c.History = append(c.History, model.CauseEvent{
				At:   e.now(),
				Kind: "scope_narrowed",
				Detail: fmt.Sprintf("边 %s->%s 在 %s 撤回，告警 %s 移出影响范围",
					sup.ParentSource, sup.ChildSource, r.Version, sup.AlertID),
			})
			c.UpdatedAt = e.now()
		}
		e.recordExplanation(sup.AlertID, "released", nil,
			"依赖边在 "+r.Version+" 撤回，关联范围收窄")
		e.emit("suppression_released", sup.ParentIncidentID,
			fmt.Sprintf("suppression of %s released: edge %s->%s removed in %s (judged with %s)",
				sup.AlertID, sup.ParentSource, sup.ChildSource, r.Version, sup.RuleVersion))
		report = append(report, fmt.Sprintf("解除抑制 %s：边 %s->%s 在 %s 中撤回（原判定用 %s）",
			sup.AlertID, sup.ParentSource, sup.ChildSource, r.Version, sup.RuleVersion))
	}
	if err := e.store.SaveCauses(); err != nil {
		return nil, err
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

// parentsByEvidence 仅当告警自带 DependsOn 声明、且规则依赖图确认该边时，
// 才返回处于活动状态的父事件；同一告警可命中多个独立父原因。
func (e *Engine) parentsByEvidence(a model.Alert) []*model.Incident {
	var parents []*model.Incident
	for _, dep := range a.DependsOn {
		if !e.edgeConfirmed(dep, a.Source) {
			continue
		}
		if parent := e.store.ActiveIncidentBySource(dep); parent != nil {
			parents = append(parents, parent)
		}
	}
	return parents
}

func (e *Engine) edgeConfirmed(parent, child string) bool {
	for _, edge := range e.store.Rules.Dependencies {
		if edge.Parent == parent && edge.Child == child {
			return true
		}
	}
	return false
}

// ---------- 多原因关联 ----------

// CauseView 是一个原因的可查看状态：当前状态、解释历史与它当前影响的告警。
type CauseView struct {
	Cause            model.Cause
	AffectedAlertIDs []string
}

// CauseViews 返回全部原因的当前状态（已确认/待核实/被撤回）及各自
// 当前影响的告警，供操作者查看。
func (e *Engine) CauseViews() []CauseView {
	var views []CauseView
	for _, c := range e.store.Causes {
		views = append(views, CauseView{Cause: *c, AffectedAlertIDs: e.alertsAffectedBy(c.ID)})
	}
	return views
}

func (e *Engine) alertsAffectedBy(causeID string) []string {
	seen := map[string]bool{}
	var ids []string
	for _, sup := range e.store.Suppressions {
		if sup.CauseID == causeID && sup.Status == model.SuppressionActive && !seen[sup.AlertID] {
			seen[sup.AlertID] = true
			ids = append(ids, sup.AlertID)
		}
	}
	sort.Strings(ids)
	return ids
}

// activeConfirmedCauses 返回某告警当前仍覆盖它的已确认原因 ID。
func (e *Engine) activeConfirmedCauses(alertID string) []string {
	seen := map[string]bool{}
	var ids []string
	for _, sup := range e.store.SuppressionsFor(alertID) {
		if seen[sup.CauseID] {
			continue
		}
		if c := e.store.FindCause(sup.CauseID); c != nil && c.Status == model.CauseConfirmed {
			seen[sup.CauseID] = true
			ids = append(ids, sup.CauseID)
		}
	}
	sort.Strings(ids)
	return ids
}

// registerCauseForIncident 为开立的父事件注册一个已确认原因；
// 按事件 ID 去重，重复观察不会增加虚假原因。
func (e *Engine) registerCauseForIncident(inc *model.Incident) error {
	if e.store.FindCauseByIncident(inc.ID) != nil {
		return nil
	}
	now := e.now()
	return e.store.AppendCause(&model.Cause{
		ID:           "cause-" + inc.ID,
		Title:        fmt.Sprintf("%s %s epoch %d", inc.Source, inc.Check, inc.Epoch),
		Status:       model.CauseConfirmed,
		ParentSource: inc.Source,
		IncidentID:   inc.ID,
		RuleVersion:  e.store.Rules.Version,
		CreatedAt:    now,
		UpdatedAt:    now,
		History: []model.CauseEvent{
			{At: now, Kind: "registered", Detail: "父事件开立，原因确认"},
		},
	})
}

// ReportCause 操作者报告一个可疑原因，状态为待核实；待核实原因绝不抑制
// 任何告警。相同 ID 重复报告不新增原因，返回是否真正新增。
func (e *Engine) ReportCause(id, title, source string) (*model.Cause, bool, error) {
	if c := e.store.FindCause(id); c != nil {
		return c, false, nil
	}
	now := e.now()
	c := &model.Cause{
		ID:           id,
		Title:        title,
		Status:       model.CausePending,
		ParentSource: source,
		RuleVersion:  e.store.Rules.Version,
		CreatedAt:    now,
		UpdatedAt:    now,
		History: []model.CauseEvent{
			{At: now, Kind: "registered", Detail: "操作者报告的可疑原因，待核实"},
		},
	}
	if err := e.store.AppendCause(c); err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// ConfirmCause 把待核实原因标记为已确认。
func (e *Engine) ConfirmCause(id string) error {
	c := e.store.FindCause(id)
	if c == nil {
		return fmt.Errorf("no cause %s", id)
	}
	if c.Status != model.CausePending {
		return fmt.Errorf("cause %s is %s, not pending", id, c.Status)
	}
	c.Status = model.CauseConfirmed
	c.UpdatedAt = e.now()
	c.History = append(c.History, model.CauseEvent{
		At: e.now(), Kind: "confirmed", Detail: "操作者核实后确认",
	})
	return e.store.SaveCauses()
}

// CausePreview 是预演移除某个原因的结果，不落任何状态。
type CausePreview struct {
	CauseID      string
	CauseStatus  string
	WouldRelease []string // 移除后将失去全部已确认原因、需要重新通知的告警
	WouldKeep    []string // 仍被其他已确认原因覆盖、保持抑制的告警
}

// PreviewRemoveCause 预演移除某个原因：只计算受影响的通知决定，不改状态。
func (e *Engine) PreviewRemoveCause(causeID string) (*CausePreview, error) {
	c := e.store.FindCause(causeID)
	if c == nil {
		return nil, fmt.Errorf("no cause %s", causeID)
	}
	p := &CausePreview{CauseID: causeID, CauseStatus: c.Status}
	for _, alertID := range e.alertsAffectedBy(causeID) {
		kept := false
		for _, other := range e.activeConfirmedCauses(alertID) {
			if other != causeID {
				kept = true
				break
			}
		}
		if kept {
			p.WouldKeep = append(p.WouldKeep, alertID)
		} else {
			p.WouldRelease = append(p.WouldRelease, alertID)
		}
	}
	return p, nil
}

// RemoveCause 确认移除某个原因：只改变受影响告警的通知决定，
// 已经发出的通知保留原依据，不做任何改动。
func (e *Engine) RemoveCause(causeID string) ([]string, error) {
	c := e.store.FindCause(causeID)
	if c == nil {
		return nil, fmt.Errorf("no cause %s", causeID)
	}
	return e.withdrawCause(c, "操作者预演后确认移除")
}

func (e *Engine) withdrawCauseForIncident(inc *model.Incident, reason string) ([]string, error) {
	c := e.store.FindCauseByIncident(inc.ID)
	if c == nil {
		return nil, nil
	}
	return e.withdrawCause(c, reason)
}

// withdrawCause 撤回原因并重新评估受它影响的告警：仍有其他已确认原因的
// 告警保持抑制（不重新通知）；失去全部已确认原因的告警才改变通知决定。
func (e *Engine) withdrawCause(c *model.Cause, reason string) ([]string, error) {
	var lines []string
	if c.Status != model.CauseWithdrawn {
		c.Status = model.CauseWithdrawn
		c.EndedAt = e.now()
		c.UpdatedAt = e.now()
		c.History = append(c.History, model.CauseEvent{
			At: e.now(), Kind: "withdrawn", Detail: reason,
		})
		if err := e.store.SaveCauses(); err != nil {
			return nil, err
		}
	}
	affected := map[string]bool{}
	for i := range e.store.Suppressions {
		sup := &e.store.Suppressions[i]
		if sup.CauseID == c.ID && sup.Status == model.SuppressionActive {
			sup.Status = model.SuppressionReleased
			sup.EndedAt = e.now()
			affected[sup.AlertID] = true
		}
	}
	var alertIDs []string
	for id := range affected {
		alertIDs = append(alertIDs, id)
	}
	sort.Strings(alertIDs)
	for _, alertID := range alertIDs {
		remaining := e.activeConfirmedCauses(alertID)
		if len(remaining) == 0 {
			e.emit("alert_released", c.IncidentID,
				fmt.Sprintf("alert %s released: %s", alertID, reason))
			e.recordExplanation(alertID, "released", nil,
				"已无已确认原因覆盖："+reason)
			lines = append(lines, "重新通知 "+alertID)
		} else {
			e.recordExplanation(alertID, "suppressed", remaining,
				"仍被 "+strings.Join(remaining, ",")+" 覆盖，不重新通知")
			lines = append(lines, fmt.Sprintf("保持抑制 %s（仍有 %d 个已确认原因）", alertID, len(remaining)))
		}
	}
	return lines, e.store.SaveSuppressions()
}

// SubmitDecisionReport 接收外部对某告警通知决定的回报。旧决定的回报
// （Seq 不新于当前解释）不得覆盖新解释，直接拒绝并返回 false。
func (e *Engine) SubmitDecisionReport(alertID string, seq int, decision, basis string) (bool, error) {
	if cur := e.store.CurrentExplanation(alertID); cur != nil && seq <= cur.Seq {
		return false, nil
	}
	if err := e.store.AppendExplanation(model.Explanation{
		AlertID:     alertID,
		Decision:    decision,
		Basis:       "外部回报：" + basis,
		RuleVersion: e.store.Rules.Version,
		At:          e.now(),
	}); err != nil {
		return false, err
	}
	return true, nil
}

func (e *Engine) recordExplanation(alertID, decision string, causeIDs []string, basis string) {
	_ = e.store.AppendExplanation(model.Explanation{
		AlertID:     alertID,
		Decision:    decision,
		CauseIDs:    causeIDs,
		Basis:       basis,
		RuleVersion: e.store.Rules.Version,
		At:          e.now(),
	})
}
