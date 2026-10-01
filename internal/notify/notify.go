// Package notify 定义通知出口；当前只记录不真正发送，后续再接通知通道。
package notify

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Event 是一条通知记录。Kind 取值：incident_opened | incident_resolved |
// alert_suppressed | suppression_lifted | suppression_released | suppression_reinstated。
type Event struct {
	Kind       string    `json:"kind"`
	IncidentID string    `json:"incident_id"`
	Detail     string    `json:"detail"`
	At         time.Time `json:"at"`
}

type Notifier interface {
	Notify(ev Event) error
}

func key(ev Event) string {
	return ev.Kind + "|" + ev.IncidentID + "|" + ev.Detail
}

// Recording 把通知事件记在内存里，绝不外发；完全相同的通知去重，
// 重复重放同一条告警不会产生多份通知。
type Recording struct {
	Events []Event
	seen   map[string]bool
}

func (r *Recording) Notify(ev Event) error {
	if r.seen == nil {
		r.seen = map[string]bool{}
		for _, e := range r.Events {
			r.seen[key(e)] = true
		}
	}
	k := key(ev)
	if r.seen[k] {
		return nil
	}
	r.seen[k] = true
	r.Events = append(r.Events, ev)
	return nil
}

// FileRecording 把通知写入本地文件（且只写本地），重启后仍保留；
// 以 kind+incident+detail 去重，重放不产生多份通知。
type FileRecording struct {
	path string
	rec  Recording
}

func NewFileRecording(dir string) (*FileRecording, error) {
	f := &FileRecording{path: filepath.Join(dir, "notifications.json")}
	data, err := os.ReadFile(f.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &f.rec.Events); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *FileRecording) Notify(ev Event) error {
	before := len(f.rec.Events)
	if err := f.rec.Notify(ev); err != nil {
		return err
	}
	if len(f.rec.Events) == before {
		return nil // 重复通知，不落盘
	}
	data, err := json.MarshalIndent(f.rec.Events, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

func (f *FileRecording) Events() []Event { return f.rec.Events }
