package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"alertcorr/internal/model"
	"alertcorr/internal/notify"
	"alertcorr/internal/store"
)

// Engine 是告警关联运行系统的核心：接收原始告警，按当前规则版本把
// 同一故障的重复告警归并为事件，并依据显式依赖证据抑制子告警。
type Engine struct {
	store *store.Store
	sink  notify.Sink

	rules  []model.RuleSet
	alerts []model.Alert
	events []*model.Event

	// UnmatchedResolves 记录无法配对到当前开放轮次的恢复（例如迟到恢复）。
	UnmatchedResolves []string
}

func New(st *store.Store, sink notify.Sink) *Engine {
	return &Engine{store: st, sink: sink}
}

// Load 从磁盘恢复规则、原始告警与事件身份（重启入口）。
func (e *Engine) Load() error {
	rules, err := e.store.LoadRules()
	if err != nil {
		return err
	}
	alerts, err := e.store.LoadAlerts()
	if err != nil {
		return err
	}
	events, err := e.store.LoadEvents()
	if err != nil {
		return err
	}
	e.rules, e.alerts, e.events = rules, alerts, events
	return nil
}

// PublishRules 发布一个新版本的规则集合，旧版本保留。
func (e *Engine) PublishRules(rs model.RuleSet) error {
	e.rules = append(e.rules, rs)
	return e.store.SaveRules(e.rules)
}

func (e *Engine) ActiveRules() *model.RuleSet {
	if len(e.rules) == 0 {
		return nil
	}
	return &e.rules[len(e.rules)-1]
}

func (e *Engine) Alerts() []model.Alert  { return append([]model.Alert(nil), e.alerts...) }
func (e *Engine) Events() []*model.Event { return append([]*model.Event(nil), e.events...) }

// Ingest 接收一条原始告警：先原样落盘，再重建关联状态并发送通知（录制，不外发）。
func (e *Engine) Ingest(a model.Alert) error {
	for _, ex := range e.alerts {
		if ex.ID == a.ID {
			return fmt.Errorf("duplicate alert id %q", a.ID)
		}
	}
	e.alerts = append(e.alerts, a)
	if err := e.store.AppendAlert(e.alerts); err != nil {
		return err
	}
	return e.rebuildAndEmit()
}

func eventID(fp string) string {
	sum := sha256.Sum256([]byte(fp))
	return "evt_" + hex.EncodeToString(sum[:6])
}

type parentHit struct {
	event  *model.Event
	path   []string
	reason string
}

// findParent 沿显式依赖边向上查找在 t 时刻处于开放状态的最近父故障事件。
// 仅承认规则中明确声明的依赖，绝不使用消息相似度。
func (e *Engine) findParent(childSvc string, t time.Time) *parentHit {
	rules := e.ActiveRules()
	if rules == nil {
		return nil
	}
	children := map[string][]model.Dep{}
	for _, d := range rules.Deps {
		children[d.Child] = append(children[d.Child], d)
	}
	type node struct {
		svc  string
		path []string
	}
	queue := []node{{svc: childSvc, path: []string{childSvc}}}
	seen := map[string]bool{childSvc: true}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, d := range children[cur.svc] {
			if seen[d.Parent] {
				continue
			}
			seen[d.Parent] = true
			path := append(append([]string{}, cur.path...), d.Parent)
			for _, ev := range e.events {
				if ev.RootService == d.Parent && ev.Status == model.EventOpen &&
					!ev.OpenedAt.After(t) && (ev.ResolvedAt.IsZero() || !ev.ResolvedAt.Before(t)) {
					return &parentHit{
						event:  ev,
						path:   path,
						reason: fmt.Sprintf("规则 %s 显式依赖链 %v；父事件 %s 在该时刻开放", rules.Version, path, ev.ID),
					}
				}
			}
			queue = append(queue, node{svc: d.Parent, path: path})
		}
	}
	return nil
}

func (e *Engine) findEventByFingerprint(fp string) *model.Event {
	for _, ev := range e.events {
		if ev.Fingerprint == fp {
			return ev
		}
	}
	return nil
}

// rebuild 依据规则对全部原始告警按故障时间线重放，得到确定的事件集合。
// 事件身份由（规则身份 + 服务 + 资源 + 本轮 StartsAt）派生，故重启可精确复现。
func (e *Engine) rebuild() []*model.Event {
	rules := e.ActiveRules()
	e.events = nil
	e.UnmatchedResolves = nil
	if rules == nil {
		return nil
	}

	ordered := append([]model.Alert(nil), e.alerts...)
	sort.SliceStable(ordered, func(i, j int) bool {
		ti, tj := ordered[i].StartsAt, ordered[j].StartsAt
		if ordered[i].Status == model.AlertResolved {
			ti = ordered[i].EndsAt
		}
		if ordered[j].Status == model.AlertResolved {
			tj = ordered[j].EndsAt
		}
		if ti.Equal(tj) {
			return ordered[i].ReceivedAt.Before(ordered[j].ReceivedAt)
		}
		return ti.Before(tj)
	})

	// suppressedOwner 记录被抑制子告警 -> 归属父事件，供其恢复告警归位。
	suppressedOwner := map[string]*model.Event{}

	for _, a := range ordered {
		if a.Status == model.AlertFiring {
			if parent := e.findParent(a.Service, a.StartsAt); parent != nil {
				ev := parent.event
				if !ev.HasSource(a.ID) {
					ev.Sources = append(ev.Sources, model.Source{
						AlertID: a.ID, Service: a.Service, Resource: a.Resource,
						Status: a.Status, Role: "suppressed_child", At: a.StartsAt,
					})
					ev.Suppressions = append(ev.Suppressions, model.Suppression{
						ChildService: a.Service, ChildAlertID: a.ID,
						ParentService: ev.RootService, ParentEventID: ev.ID,
						RuleVersion: rules.Version, Reason: parent.reason, SuppressedAt: a.StartsAt,
					})
					suppressedOwner[a.Fingerprint()] = ev
				}
				if a.StartsAt.After(ev.LastUpdateAt) {
					ev.LastUpdateAt = a.StartsAt
				}
				continue
			}
			if ev := e.findEventByFingerprint(a.Fingerprint()); ev != nil {
				if !ev.HasSource(a.ID) {
					ev.Sources = append(ev.Sources, model.Source{
						AlertID: a.ID, Service: a.Service, Resource: a.Resource,
						Status: a.Status, Role: "duplicate", At: a.StartsAt,
					})
				}
				if a.StartsAt.After(ev.LastUpdateAt) {
					ev.LastUpdateAt = a.StartsAt
				}
				continue
			}
			fp := a.Fingerprint()
			ev := &model.Event{
				ID: eventID(fp), Fingerprint: fp,
				RootService: a.Service, RootResource: a.Resource,
				Status: model.EventOpen, OpenedAt: a.StartsAt,
				TriggerStartsAt: a.StartsAt, LastUpdateAt: a.StartsAt,
				RuleVersion: rules.Version,
				Title:       fmt.Sprintf("%s/%s 故障", a.Service, a.Resource),
				Sources: []model.Source{{
					AlertID: a.ID, Service: a.Service, Resource: a.Resource,
					Status: a.Status, Role: "root", At: a.StartsAt,
				}},
			}
			e.events = append(e.events, ev)
			continue
		}

		// 恢复必须携带所属轮次的 StartsAt，且按发生时间处理，只关闭同一轮次的事件。
		resolveAt := a.EndsAt
		if resolveAt.IsZero() {
			resolveAt = a.ReceivedAt
		}
		if owner := suppressedOwner[a.Fingerprint()]; owner != nil {
			// 被抑制子告警的恢复只作为来源记录，不影响父事件生命周期。
			if !owner.HasSource(a.ID) {
				owner.Sources = append(owner.Sources, model.Source{
					AlertID: a.ID, Service: a.Service, Resource: a.Resource,
					Status: a.Status, Role: "suppressed_child", At: resolveAt,
				})
			}
			continue
		}
		ev := e.findEventByFingerprint(a.Fingerprint())
		if ev == nil {
			e.UnmatchedResolves = append(e.UnmatchedResolves, a.ID)
			continue
		}
		// 事件已关闭且同身份的新一轮已经开启：这是上一轮的迟到恢复，忽略，
		// 绝不能用它关闭新一轮开放中的事件。
		if ev.Status == model.EventResolved {
			stale := false
			// 迟到恢复到达前，同身份新一轮故障已经触发：忽略，不得影响新一轮。
			for _, b := range e.alerts {
				if b.Status == model.AlertFiring && b.Service == ev.RootService &&
					b.Resource == ev.RootResource && b.StartsAt.After(ev.TriggerStartsAt) &&
					!b.StartsAt.After(a.ReceivedAt) {
					stale = true
				}
			}
			if stale {
				e.UnmatchedResolves = append(e.UnmatchedResolves, a.ID)
				continue
			}
		}
		// 关键防护：只有轮次起点一致才允许关闭，迟到恢复不能关闭新一轮事件。
		if !ev.TriggerStartsAt.Equal(a.StartsAt) {
			e.UnmatchedResolves = append(e.UnmatchedResolves, a.ID)
			continue
		}
		if ev.Status == model.EventOpen {
			ev.Status = model.EventResolved
			ev.ResolvedAt = resolveAt
			ev.LastUpdateAt = resolveAt
			if !ev.HasSource(a.ID) {
				ev.Sources = append(ev.Sources, model.Source{
					AlertID: a.ID, Service: a.Service, Resource: a.Resource,
					Status: a.Status, Role: "root", At: resolveAt,
				})
			}
		} else if !ev.HasSource(a.ID) {
			ev.Sources = append(ev.Sources, model.Source{
				AlertID: a.ID, Service: a.Service, Resource: a.Resource,
				Status: a.Status, Role: "duplicate", At: resolveAt,
			})
		}
	}

	sort.Slice(e.events, func(i, j int) bool { return e.events[i].OpenedAt.Before(e.events[j].OpenedAt) })
	return e.events
}

// rebuildAndEmit 重建状态、与旧状态对比后录制通知差异，并持久化事件。
func (e *Engine) rebuildAndEmit() error {
	old := map[string]*model.Event{}
	oldSup := map[string]bool{}
	for _, ev := range e.events {
		old[ev.ID] = ev
		for _, s := range ev.Suppressions {
			oldSup[s.ChildAlertID] = true
		}
	}

	newEvents := e.rebuild()
	for _, ev := range newEvents {
		prev, existed := old[ev.ID]
		if !existed {
			_ = e.sink.Send(notify.DescribeEvent("event_opened", ev, nil))
		} else if prev.Status == model.EventOpen && ev.Status == model.EventResolved {
			_ = e.sink.Send(notify.DescribeEvent("event_resolved", ev, nil))
		}
		for i := range ev.Suppressions {
			s := &ev.Suppressions[i]
			if !existed || !oldSup[s.ChildAlertID] {
				_ = e.sink.Send(notify.DescribeEvent("child_suppressed", ev, s))
			}
		}
	}
	return e.store.SaveEvents(e.events)
}
