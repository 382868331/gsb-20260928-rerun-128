package notify

import (
	"fmt"
	"sync"
	"time"

	"alertcorr/internal/model"
)

// Message 是一条待投递的通知。后续接入真实通道时只需实现 Sink。
type Message struct {
	Kind      string    `json:"kind"` // "event_opened" | "event_resolved" | "child_suppressed"
	EventID   string    `json:"event_id"`
	Service   string    `json:"service"`
	Title     string    `json:"title"`
	Text      string    `json:"text"`
	EmittedAt time.Time `json:"emitted_at"`
}

// Sink 是通知通道接口。当前系统不真的发送通知。
type Sink interface {
	Send(msg Message) error
}

// RecordingSink 只在内存（以及通过 Log 持久化的演示输出）中记录通知，
// 不触碰任何真实通道，方便核对“本应发出”的通知。
type RecordingSink struct {
	mu  sync.Mutex
	log []Message
}

func NewRecordingSink() *RecordingSink { return &RecordingSink{} }

func (r *RecordingSink) Send(msg Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, msg)
	return nil
}

func (r *RecordingSink) Log() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Message(nil), r.log...)
}

func (r *RecordingSink) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = nil
}

// DescribeEvent 生成通知文案（不发送）。
func DescribeEvent(kind string, ev *model.Event, sup *model.Suppression) Message {
	msg := Message{Kind: kind, EventID: ev.ID, Service: ev.RootService, Title: ev.Title, EmittedAt: time.Now().UTC()}
	switch kind {
	case "event_opened":
		msg.Text = fmt.Sprintf("事件开启：%s/%s（规则版本 %s，来源 %d 条）", ev.RootService, ev.RootResource, ev.RuleVersion, len(ev.Sources))
	case "event_resolved":
		msg.Text = fmt.Sprintf("事件恢复：%s/%s，持续来源 %d 条", ev.RootService, ev.RootResource, len(ev.Sources))
	case "child_suppressed":
		if sup != nil {
			msg.Text = fmt.Sprintf("子告警 %s 被父故障 %s（事件 %s）抑制：%s", sup.ChildService, sup.ParentService, sup.ParentEventID, sup.Reason)
		}
	}
	return msg
}
