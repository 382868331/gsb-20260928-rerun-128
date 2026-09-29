// Package notify 定义通知出口；当前只记录不真正发送，后续再接通知通道。
package notify

import "time"

type Event struct {
	Kind       string    `json:"kind"` // incident_opened | incident_resolved | alert_suppressed
	IncidentID string    `json:"incident_id"`
	Detail     string    `json:"detail"`
	At         time.Time `json:"at"`
}

type Notifier interface {
	Notify(ev Event) error
}

// Recording 把通知事件记在内存里，绝不外发。
type Recording struct {
	Events []Event
}

func (r *Recording) Notify(ev Event) error {
	r.Events = append(r.Events, ev)
	return nil
}
