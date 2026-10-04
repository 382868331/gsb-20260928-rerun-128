// Package correlator 实现告警关联引擎：
// 同一故障的重复告警归并为一个事件，处理恢复与再次发生，
// 父故障在有显式依赖证据时抑制子告警；同一告警可同时挂多条独立的
// 原因解释（已确认/待核实/被撤回），只有全部已确认原因都消失才重新通知。
// 绝不按消息相似度合并。
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
	OutcomeSuspected       Outcome = "suspected"        // 存在待核实原因，但仍独立通知
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
	// 同一指纹已有同轮（或更新轮次）事件：这是重复观察，只并入来源，
	// 绝不新开事件、不新造原因、不改写既有通知决定。先于原因更新处理，
	// 保证重复观察不会增加任何虚假原因。
	if prior := e.store.LatestIncident(a.Fingerprint); prior != nil && a.Epoch <= prior.Epoch {
		prior.AlertIDs = appendIfMissing(prior.AlertIDs, a.ID)
		// 重复观察可能补到显式依赖证据：允许把既有 suspected 解释升级，
		// 但不复活任何已撤回（含被操作者移除）的解释。
		changed, err := e.updateCauses(a, nil)
		if err != nil {
			return Result{}, err
		}
		if err := e.store.SaveIncidents(); err != nil {
			return Result{}, err
		}
		if changed {
			if err := e.reconcile(); err != nil {
				return Result{}, err
			}
			// 后补证据把 suspected 升级为 confirmed：若该主体仍是活动事件，
			// 由已确认父事件吸收为抑制（父告警迟到+证据后补路径）。
			if prior.Status == model.IncidentActive && len(e.store.ActiveConfirmedParents(a.Fingerprint)) > 0 {
				for psrc := range e.store.ActiveConfirmedParents(a.Fingerprint) {
					if p := e.store.ActiveIncidentBySource(psrc); p != nil {
						if err := e.absorbIncident(prior, p); err != nil {
							return Result{}, err
						}
					}
				}
				return Result{OutcomeSuppressed, prior.ID}, nil
			}
		}
		if len(e.store.ActiveConfirmedParents(a.Fingerprint)) > 0 {
			return Result{OutcomeSuppressed, prior.ID}, nil
		}
		return Result{OutcomeMerged, prior.ID}, nil
	}

	// 先按当前证据更新/建立该告警针对每个候选父事件的原因解释。
	changed, err := e.updateCauses(a, nil)
	if err != nil {
		return Result{}, err
	}

	// 有已确认原因：抑制。多个独立原因中只要剩一条 confirmed 即继续抑制。
	if parents := e.store.ActiveConfirmedParents(a.Fingerprint); len(parents) > 0 {
		if err := e.applySuppression(a, parents); err != nil {
			return Result{}, err
		}
		var pid string
		for p := range parents {
			if inc := e.store.ActiveIncidentBySource(p); inc != nil {
				pid = inc.ID
				break
			}
		}
		return Result{OutcomeSuppressed, pid}, nil
	}

	// 无已确认原因但有活动父事件命中规则图：记为“待核实”的可疑解释，
	// 但绝不因此压掉这条本应独立发出的通知。
	hasSuspect := false
	for _, x := range e.store.ExplanationsFor(a.Fingerprint) {
		if x.State == model.ExplSuspected && e.store.ParentIncidentActive(x.ParentIncidentID) {
			hasSuspect = true
		}
	}

	_ = changed
	if inc := e.store.ActiveIncident(a.Fingerprint); inc != nil {
		// 来源未走恢复就直接新一轮：旧事件按新轮次更替前先关闭。
		inc.Status = model.IncidentResolved
		inc.ResolvedAt = a.StartsAt
		e.emit("incident_resolved", inc.ID, "superseded by new epoch")
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
	// 父告警可能迟到：父事件开立后为所有规则图命中的活动子事件补原因解释；
	// 带显式依赖证据的子事件被吸收为已确认抑制，其余仅记待核实。
	if err := e.attachCausesForNewParent(inc); err != nil {
		return Result{}, err
	}
	// 独立事件开立后，再为规则图命中、但无显式证据的活动父事件补“待核实”解释
	//（仅记录，不抑制），使状态可查看，同时独立告警已及时通知。
	if _, err := e.updateCauses(a, inc); err != nil {
		return Result{}, err
	}
	if hasSuspect {
		return Result{Outcome: OutcomeSuspected, IncidentID: inc.ID}, nil
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
	// 该父事件作为原因的全部解释随之撤回；子告警若还有别的已确认原因
	// 则继续抑制，只有最后一条消失时才重新通知。
	if err := e.reconcile(); err != nil {
		return Result{}, err
	}
	return Result{OutcomeResolved, inc.ID}, nil
}

// updateCauses 根据一条 firing 观察更新其原因解释：
//   - 对规则图中每个命中、且父源有活动事件的边建立/复用一条解释；
//   - 告警显式声明 DependsOn 者为 confirmed，否则仅 suspected；
//   - 同一 (子身份, 父源) 只保留一条解释，重复观察不会增加虚假原因；
//   - 后补的显式证据可把 suspected 升级为 confirmed。
//
// attachingIncident 非 nil 时表示该告警刚开立独立事件，允许为无显式
// 证据的活动父事件记录 suspected 解释（不抑制）；为 nil 时只处理
// confirmed 与已存在解释，可疑原因绝不压掉独立通知。
func (e *Engine) updateCauses(a model.Alert, attachingIncident *model.Incident) (bool, error) {
	changed := false
	declared := map[string]bool{}
	for _, dep := range a.DependsOn {
		declared[dep] = true
	}
	for _, edge := range e.store.Rules.Dependencies {
		if edge.Child != a.Source {
			continue
		}
		parent := e.store.ActiveIncidentBySource(edge.Parent)
		if parent == nil {
			continue
		}
		x := e.store.FindExplanation(a.Fingerprint, edge.Parent)
		if x != nil && !x.Active() {
			// 操作者移除的解释不自动复活；针对同一父事件已撤回的也不复活；
			// 其余（旧父事件已恢复/边曾撤回）允许在新父事件下重建。
			if x.EndReason == model.EndOperatorRemoved || x.ParentIncidentID == parent.ID {
				continue
			}
			x = nil
		}
		want := model.ExplSuspected
		basisKind := model.BasisSuspected
		if declared[edge.Parent] {
			want = model.ExplConfirmed
			basisKind = model.BasisDeclared
		}
		if x == nil && want == model.ExplSuspected {
			if attachingIncident == nil {
				continue
			}
			x = e.newExplanation(a, edge.Parent, parent, attachingIncident.ID, want, basisKind)
			e.store.Explanations = append(e.store.Explanations, x)
			changed = true
			continue
		}
		if x == nil {
			// 若该主体对此父源曾有解释（已被操作者移除/针对同事件撤回），
			// 重复观察不得借新声明重建；但其它父源的历史不影响本父源。
			if attachingIncident == nil && e.hadHistoryFor(a.Fingerprint, edge.Parent) {
				continue
			}
			x = e.newExplanation(a, edge.Parent, parent, a.ID, want, basisKind)
			e.store.Explanations = append(e.store.Explanations, x)
			changed = true
			continue
		}
		if !contains(x.AlertIDs, a.ID) {
			x.AlertIDs = append(x.AlertIDs, a.ID)
			x.Scope = append(x.Scope, a.ID)
			changed = true
		}
		if want == model.ExplConfirmed && x.State != model.ExplConfirmed {
			x.SetState(model.ExplConfirmed, "evidence_arrived",
				"explicit dependency evidence arrived with alert "+a.ID,
				e.store.Rules.Version, e.now())
			x.Basis = model.BasisDeclared
			changed = true
		}
	}
	return changed, e.store.SaveExplanations()
}

// newExplanation 建立一条原因解释（同一身份对的去重由调用方保证）。
func (e *Engine) newExplanation(a model.Alert, parentSource string,
	parent *model.Incident, subjectID, state, basisKind string) *model.Explanation {
	e.seq++
	return &model.Explanation{
		ID:               fmt.Sprintf("expl-%d", e.seq),
		AlertFingerprint: a.Fingerprint,
		SubjectID:        subjectID,
		AlertIDs:         []string{a.ID},
		ChildSource:      a.Source,
		ParentSource:     parentSource,
		ParentIncidentID: parent.ID,
		State:            state,
		Basis:            basisKind,
		RuleVersion:      e.store.Rules.Version,
		Scope:            []string{a.ID},
		CreatedAt:        e.now(),
		History: []model.StateChange{{
			To: state, Reason: "created", Detail: basisKind,
			RuleVersion: e.store.Rules.Version, At: e.now(),
		}},
	}
}

// attachCausesForNewParent 在父事件（可能迟到）开立后，为规则图命中的活动子事件
// 补建原因解释：带显式依赖证据者 confirmed 并吸收子事件，其余只记 suspected。
func (e *Engine) attachCausesForNewParent(parent *model.Incident) error {
	return e.forEachChildParent(parent)
}

// absorbIncident 把一个仍活动的子事件吸收到已确认父事件下并记录决定。
func (e *Engine) absorbIncident(child, parent *model.Incident) error {
	child.Status = model.IncidentSuppressed
	child.ResolvedAt = e.now()
	x := e.store.ActiveExplanation(child.Fingerprint, parent.Source)
	for _, id := range child.AlertIDs {
		parent.SuppressedAlertIDs = appendIfMissing(parent.SuppressedAlertIDs, id)
		e.ensureSuppression(id, child.Source, parent, x)
	}
	bases := e.basesFor(child.Fingerprint)
	e.suppressDecision(child.ID, child.Fingerprint, bases)
	e.emitBasis("alert_suppressed", parent.ID,
		fmt.Sprintf("parent %s absorbed child incident %s after evidence", parent.Source, child.ID),
		child.ID, bases)
	if err := e.store.SaveExplanations(); err != nil {
		return err
	}
	if err := e.store.SaveSuppressions(); err != nil {
		return err
	}
	return e.store.SaveIncidents()
}

func (e *Engine) forEachChildParent(parent *model.Incident) error {
	for _, child := range e.store.Incidents {
		if child.ID == parent.ID || child.Status == model.IncidentResolved {
			continue
		}
		if !e.edgeConfirmed(parent.Source, child.Source) {
			continue
		}
		x := e.store.FindExplanation(child.Fingerprint, parent.Source)
		if x != nil && !x.Active() {
			if x.EndReason == model.EndOperatorRemoved || x.ParentIncidentID == parent.ID {
				continue
			}
			x = nil
		}
		declared := e.declaresDependency(child, parent.Source)
		want := model.ExplSuspected
		basisKind := model.BasisSuspected
		if declared {
			want = model.ExplConfirmed
			basisKind = model.BasisDeclared
		}
		if x == nil {
			e.seq++
			x = &model.Explanation{
				ID:               fmt.Sprintf("expl-%d", e.seq),
				AlertFingerprint: child.Fingerprint,
				SubjectID:        child.ID,
				AlertIDs:         append([]string{}, child.AlertIDs...),
				ChildSource:      child.Source,
				ParentSource:     parent.Source,
				ParentIncidentID: parent.ID,
				State:            want,
				Basis:            basisKind,
				RuleVersion:      e.store.Rules.Version,
				Scope:            append([]string{}, child.AlertIDs...),
				CreatedAt:        e.now(),
				History: []model.StateChange{{To: want, Reason: "late_parent", Detail: basisKind,
					RuleVersion: e.store.Rules.Version, At: e.now()}},
			}
			e.store.Explanations = append(e.store.Explanations, x)
		} else if declared && x.State == model.ExplSuspected {
			x.SetState(model.ExplConfirmed, "evidence_arrived", "late parent with declared edge",
				e.store.Rules.Version, e.now())
			x.Basis = model.BasisDeclared
		}
		if x.State == model.ExplConfirmed && child.Status == model.IncidentActive {
			// 迟到父事件吸收：子事件转为抑制，告警并入父事件清单。
			child.Status = model.IncidentSuppressed
			child.ResolvedAt = e.now()
			for _, id := range child.AlertIDs {
				parent.SuppressedAlertIDs = appendIfMissing(parent.SuppressedAlertIDs, id)
				e.ensureSuppression(id, child.Source, parent, x)
			}
			bases := e.basesFor(child.Fingerprint)
			e.suppressDecision(child.ID, child.Fingerprint, bases)
			e.emitBasis("alert_suppressed", parent.ID,
				fmt.Sprintf("late parent %s absorbed child incident %s", parent.Source, child.ID),
				child.ID, bases)
		}
	}
	if err := e.store.SaveExplanations(); err != nil {
		return err
	}
	if err := e.store.SaveSuppressions(); err != nil {
		return err
	}
	return e.store.SaveIncidents()
}

// applySuppression 记录一条新告警被一个或多个已确认原因抑制的决定。
func (e *Engine) applySuppression(a model.Alert, parents map[string]bool) error {
	// 直接抑制也为子告警建立自己的 suppressed 事件，使重复观察识别、
	// 主体追踪与迟到吸收三条路径共用同一套事件身份。
	childInc := e.store.LatestIncident(a.Fingerprint)
	if childInc == nil || childInc.Epoch < a.Epoch {
		e.seq++
		childInc = &model.Incident{
			ID:          fmt.Sprintf("inc-%s-%d", a.Fingerprint, a.Epoch),
			Fingerprint: a.Fingerprint, Source: a.Source, Check: a.Check,
			Epoch: a.Epoch, Status: model.IncidentSuppressed, Severity: a.Severity,
			StartedAt: a.StartsAt, ResolvedAt: e.now(), AlertIDs: []string{a.ID},
			RuleVersion: e.store.Rules.Version,
		}
		e.store.Incidents = append(e.store.Incidents, childInc)
	}
	for psrc := range parents {
		parent := e.store.ActiveIncidentBySource(psrc)
		if parent == nil {
			continue
		}
		parent.SuppressedAlertIDs = appendIfMissing(parent.SuppressedAlertIDs, a.ID)
		x := e.store.ActiveExplanation(a.Fingerprint, psrc)
		e.ensureSuppression(a.ID, a.Source, parent, x)
	}
	bases := e.basesFor(a.Fingerprint)
	e.suppressDecision(childInc.ID, a.Fingerprint, bases)
	if err := e.store.SaveIncidents(); err != nil {
		return err
	}
	// 抑制通知按主体只发一次：首个已确认原因出现时发出，后续原因补到不重复通知。
	e.emitBasis("alert_suppressed", firstParentID(parents, e.store),
		fmt.Sprintf("alert %s from %s suppressed by %d cause(s)", a.ID, a.Source, len(parents)),
		a.ID, bases)
	return e.store.SaveSuppressions()
}

// ensureSuppression 与旧 suppressions.json 结构保持同步：每个 (子告警,父事件) 一条。
func (e *Engine) ensureSuppression(alertID, childSource string, parent *model.Incident, x *model.Explanation) {
	for i := range e.store.Suppressions {
		s := &e.store.Suppressions[i]
		if s.AlertID == alertID && s.ParentIncidentID == parent.ID {
			return
		}
	}
	e.store.Suppressions = append(e.store.Suppressions, model.Suppression{
		AlertID:          alertID,
		ChildSource:      childSource,
		ParentIncidentID: parent.ID,
		ParentSource:     parent.Source,
		RuleVersion:      e.store.Rules.Version,
		Status:           model.SuppressionActive,
		CreatedAt:        e.now(),
	})
}

// basesFor 生成某子身份当前全部活动 confirmed 解释的依据快照。
func (e *Engine) basesFor(subjectFP string) []model.Basis {
	var b []model.Basis
	for _, x := range e.store.Explanations {
		if x.AlertFingerprint == subjectFP && x.State == model.ExplConfirmed &&
			e.store.ParentIncidentActive(x.ParentIncidentID) {
			alertID := ""
			if len(x.AlertIDs) > 0 {
				alertID = x.AlertIDs[0]
			}
			b = append(b, model.Basis{
				ExplanationID: x.ID, AlertID: alertID, ParentSource: x.ParentSource,
				ParentIncidentID: x.ParentIncidentID, State: x.State, RuleVersion: x.RuleVersion,
			})
		}
	}
	return b
}

func firstParentID(parents map[string]bool, st *store.Store) string {
	for p := range parents {
		if inc := st.ActiveIncidentBySource(p); inc != nil {
			return inc.ID
		}
	}
	return ""
}

// emit 把通知写入本地记录（按 DedupKey 去重），仅新增时才交给 Notifier。
func (e *Engine) emit(kind, incidentID, detail string) {
	e.emitBasis(kind, incidentID, detail, "", nil)
}

// emitBasis 写入一条带当时依据快照的通知，按 (kind,主体,内容) 去重；
// 已发出的通知事后不改写其依据。
func (e *Engine) emitBasis(kind, incidentID, detail, subjectID string, bases []model.Basis) {
	n := model.Notification{
		Kind:       kind,
		IncidentID: incidentID,
		Detail:     detail,
		DedupKey:   kind + "|" + subjectID + "|" + detail,
		SubjectID:  subjectID,
		Basis:      bases,
		At:         e.now(),
	}
	added, err := e.store.AppendNotification(n)
	if err != nil || !added {
		return
	}
	_ = e.notifier.Notify(notify.Event{Kind: kind, IncidentID: incidentID, Detail: detail, At: n.At})
}

// suppressDecision 记录某主体当前处于抑制态及其依据；同一抑制轮次不重复处理。
func (e *Engine) suppressDecision(subjectID, fp string, bases []model.Basis) {
	session := sessionKey(bases)
	d := e.store.DecisionForFP(fp)
	if d == nil {
		e.store.Decisions = append(e.store.Decisions, model.DecisionState{
			Fingerprint: fp, SubjectID: subjectID, Session: session, Observed: true,
		})
	} else {
		d.Fingerprint = fp
		d.SubjectID = subjectID
		d.Session = session
		d.Resumed = false
		d.Observed = true
	}
	_ = e.store.SaveDecisions()
}

// reconcile 依据当前父事件与规则图状态重算所有解释与通知决定：
//   - 父事件已结束的 confirmed/suspected 解释撤回（parent_resolved）；
//   - 最后一条 confirmed 原因消失的主体发出一次 resumed 通知，
//     仍有其它 confirmed 原因的主体继续抑制；
//   - 与旧 suppressions.json 记录的状态同步。
func (e *Engine) reconcile() error {
	for _, x := range e.store.Explanations {
		if !x.Active() {
			continue
		}
		if !e.store.ParentIncidentActive(x.ParentIncidentID) {
			x.SetState(model.ExplWithdrawn, model.EndParentResolved,
				"parent incident "+x.ParentIncidentID+" resolved",
				x.RuleVersion, e.now())
			e.syncSuppressionStatus(x, model.SuppressionReleased)
			e.emit("explanation_withdrawn", x.ParentIncidentID,
				fmt.Sprintf("cause %s (%s) of %s withdrawn: parent resolved",
					x.ID, x.ParentSource, x.AlertFingerprint))
		}
	}
	if err := e.store.SaveExplanations(); err != nil {
		return err
	}
	if err := e.store.SaveSuppressions(); err != nil {
		return err
	}
	// 按主体重算：仍有 confirmed 原因则保持抑制，否则发出恰好一次 resumed。
	subjects := map[string]bool{}
	for _, x := range e.store.Explanations {
		subjects[x.AlertFingerprint] = true
	}
	for fp := range subjects {
		bases := e.basesFor(fp)
		d := e.store.DecisionForFP(fp)
		if d == nil {
			continue
		}
		subjectID := d.SubjectID
		if len(bases) > 0 {
			d.Session = sessionKey(bases)
			d.Resumed = false
			continue
		}
		if !d.Resumed {
			d.Resumed = true
			incidentID := ""
			if inc := e.store.ActiveIncident(fp); inc != nil {
				incidentID = inc.ID
			}
			e.emitBasis("alert_resumed", incidentID,
				fmt.Sprintf("all confirmed causes for %s cleared; notification resumed", subjectID),
				subjectID, nil)
		}
	}
	return e.store.SaveDecisions()
}

func (e *Engine) syncSuppressionStatus(x *model.Explanation, status string) {
	for i := range e.store.Suppressions {
		s := &e.store.Suppressions[i]
		if s.ParentIncidentID == x.ParentIncidentID &&
			(s.ChildSource == x.ChildSource || contains(x.AlertIDs, s.AlertID)) {
			if s.Status == model.SuppressionActive || s.Status == model.SuppressionLifted {
				s.Status = status
				s.EndedAt = e.now()
			}
		}
	}
}

func sessionKey(bases []model.Basis) string {
	parts := make([]string, 0, len(bases))
	for _, b := range bases {
		parts = append(parts, b.ParentIncidentID)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func appendIfMissing(list []string, v string) []string {
	if contains(list, v) {
		return list
	}
	return append(list, v)
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

// ApplyRules 应用新规则集并审查全部活动原因解释：依赖边被撤回的解释
// 撤回（保留原判定规则版本）；仍在图中的保持。边撤回后若某告警再无其它
// 已确认原因，则仅对该告警恢复通知；还有其它已确认原因的继续抑制。
func (e *Engine) ApplyRules(r model.RuleSet) ([]string, error) {
	old := e.store.Rules
	if err := e.store.SaveRules(r); err != nil {
		return nil, err
	}
	var report []string
	for _, x := range e.store.Explanations {
		if !x.Active() {
			continue
		}
		if edgeInSet(r, x.ParentSource, x.ChildSource) {
			report = append(report, fmt.Sprintf("保持原因 %s：边 %s->%s 仍在 %s（原判定用 %s）",
				x.ID, x.ParentSource, x.ChildSource, r.Version, x.RuleVersion))
			continue
		}
		x.SetState(model.ExplWithdrawn, model.EndEdgeWithdrawn,
			fmt.Sprintf("edge %s->%s removed in %s (judged with %s, prior %s)",
				x.ParentSource, x.ChildSource, r.Version, x.RuleVersion, old.Version),
			r.Version, e.now())
		e.syncSuppressionStatus(x, model.SuppressionReleased)
		report = append(report, fmt.Sprintf("撤回原因 %s：边 %s->%s 在 %s 中撤回（原判定用 %s）",
			x.ID, x.ParentSource, x.ChildSource, r.Version, x.RuleVersion))
	}
	if err := e.store.SaveExplanations(); err != nil {
		return nil, err
	}
	if err := e.store.SaveSuppressions(); err != nil {
		return nil, err
	}
	return report, e.reconcile()
}

func edgeInSet(r model.RuleSet, parent, child string) bool {
	for _, edge := range r.Dependencies {
		if edge.Parent == parent && edge.Child == child {
			return true
		}
	}
	return false
}

// CauseView 是一个告警当前全部原因解释的可查看状态。
type CauseView struct {
	SubjectID   string
	Fingerprint string
	Suppressed  bool                 // 当前是否仍被抑制（存在活动 confirmed 原因）
	Confirmed   []*model.Explanation // 已确认
	Suspected   []*model.Explanation // 待核实
	Withdrawn   []*model.Explanation // 被撤回（含原因与时间，供追溯）
	AffectsNow  []string             // 当前实际影响通知决定的原因 ID
}

// ViewCauses 返回某子告警身份的多原因关联状态，三类解释分列且保留历史。
func (e *Engine) ViewCauses(fingerprint string) CauseView {
	v := CauseView{Fingerprint: fingerprint}
	for _, x := range e.store.ExplanationsFor(fingerprint) {
		if v.SubjectID == "" {
			v.SubjectID = x.SubjectID
		}
		switch x.State {
		case model.ExplConfirmed:
			if e.store.ParentIncidentActive(x.ParentIncidentID) {
				v.Confirmed = append(v.Confirmed, x)
				v.AffectsNow = append(v.AffectsNow, x.ID)
			} else {
				// 父事件刚恢复尚未重算时也归入 withdrawn 视图。
				v.Withdrawn = append(v.Withdrawn, x)
			}
		case model.ExplSuspected:
			if e.store.ParentIncidentActive(x.ParentIncidentID) {
				v.Suspected = append(v.Suspected, x)
			} else {
				v.Withdrawn = append(v.Withdrawn, x)
			}
		default:
			v.Withdrawn = append(v.Withdrawn, x)
		}
	}
	v.Suppressed = len(v.Confirmed) > 0
	return v
}

// RemovalPreview 是“移除某个原因”的预演结果，不产生任何持久化改动。
type RemovalPreview struct {
	Explanation    *model.Explanation
	WouldResume    []string // 移除后将恢复通知的主体（这是最后一条已确认原因）
	StaySuppressed []string // 移除后仍被其它已确认原因抑制的主体
	OtherCauses    []string // 仍然存在的其它已确认原因 ID
}

// PreviewRemoveCause 预演移除一条原因解释的后果，但不改变任何状态。
func (e *Engine) PreviewRemoveCause(explID string) (*RemovalPreview, error) {
	x := e.findExplanationByID(explID)
	if x == nil {
		return nil, fmt.Errorf("no explanation %s", explID)
	}
	p := &RemovalPreview{Explanation: x}
	for _, other := range e.store.ExplanationsFor(x.AlertFingerprint) {
		if other.ID == x.ID || other.State != model.ExplConfirmed {
			continue
		}
		if !e.store.ParentIncidentActive(other.ParentIncidentID) {
			continue
		}
		p.OtherCauses = append(p.OtherCauses, other.ID)
	}
	if len(p.OtherCauses) > 0 {
		p.StaySuppressed = append(p.StaySuppressed, x.SubjectID)
	} else if x.State == model.ExplConfirmed {
		p.WouldResume = append(p.WouldResume, x.SubjectID)
	}
	return p, nil
}

// ConfirmRemoveCause 确认预演：撤回该原因（operator_removed），随后只重算
// 受影响主体的通知决定；已经发出的通知保留其原始依据，不被改写。
// 被操作者移除的原因不会因后续重复观察自动复活。
func (e *Engine) ConfirmRemoveCause(explID string) (*RemovalPreview, error) {
	p, err := e.PreviewRemoveCause(explID)
	if err != nil {
		return nil, err
	}
	x := p.Explanation
	if x.Active() {
		x.SetState(model.ExplWithdrawn, model.EndOperatorRemoved,
			"operator removed cause after preview", e.store.Rules.Version, e.now())
		e.syncSuppressionStatus(x, model.SuppressionReleased)
		if err := e.store.SaveExplanations(); err != nil {
			return nil, err
		}
		if err := e.store.SaveSuppressions(); err != nil {
			return nil, err
		}
		if err := e.reconcile(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// NarrowScope 把一条原因解释的关联范围收窄到给定告警集合，历史中保留
// 收窄前后的范围快照；收窄后不再被该原因覆盖的告警改由其它原因决定。
func (e *Engine) NarrowScope(explID string, keepAlertIDs []string) error {
	x := e.findExplanationByID(explID)
	if x == nil {
		return fmt.Errorf("no explanation %s", explID)
	}
	kept := map[string]bool{}
	for _, id := range keepAlertIDs {
		kept[id] = true
	}
	var narrowed []string
	for _, id := range x.Scope {
		if kept[id] {
			narrowed = append(narrowed, id)
		}
	}
	x.RecordScope("scope_narrowed",
		fmt.Sprintf("scope %v -> %v in %s", x.Scope, narrowed, e.store.Rules.Version),
		e.store.Rules.Version, e.now())
	x.Scope = narrowed
	return e.store.SaveExplanations()
}

func (e *Engine) findExplanationByID(id string) *model.Explanation {
	for _, x := range e.store.Explanations {
		if x.ID == id {
			return x
		}
	}
	return nil
}

// hadHistoryFor 报告该主体对此父源是否已存在（哪怕已撤回）的解释，
// 用于阻止重复观察复活被移除的原因。
func (e *Engine) hadHistoryFor(subjectFP, parentSource string) bool {
	for _, x := range e.store.Explanations {
		if x.AlertFingerprint == subjectFP && x.ParentSource == parentSource {
			return true
		}
	}
	return false
}

func (e *Engine) edgeConfirmed(parent, child string) bool {
	for _, edge := range e.store.Rules.Dependencies {
		if edge.Parent == parent && edge.Child == child {
			return true
		}
	}
	return false
}
