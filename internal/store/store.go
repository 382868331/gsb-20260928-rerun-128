// Package store 用 JSON 文件分别保存规则版本、原始告警、事件身份和抑制关系。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"alertcorr/internal/model"
)

type Store struct {
	dir string

	Rules         model.RuleSet
	Alerts        []model.Alert
	Incidents     []*model.Incident
	Suppressions  []model.Suppression
	Notifications []model.Notification
	Causes        []*model.Cause
	Explanations  []model.Explanation
}

func Open(dir string) (*Store, error) {
	s := &Store{dir: dir}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	read := func(name string, v any) error {
		data, err := os.ReadFile(filepath.Join(s.dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(data, v)
	}
	if err := read("rules.json", &s.Rules); err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	if err := read("alerts.json", &s.Alerts); err != nil {
		return fmt.Errorf("load alerts: %w", err)
	}
	if err := read("incidents.json", &s.Incidents); err != nil {
		return fmt.Errorf("load incidents: %w", err)
	}
	if err := read("suppressions.json", &s.Suppressions); err != nil {
		return fmt.Errorf("load suppressions: %w", err)
	}
	if err := read("notifications.json", &s.Notifications); err != nil {
		return fmt.Errorf("load notifications: %w", err)
	}
	if err := read("causes.json", &s.Causes); err != nil {
		return fmt.Errorf("load causes: %w", err)
	}
	if err := read("explanations.json", &s.Explanations); err != nil {
		return fmt.Errorf("load explanations: %w", err)
	}
	return nil
}

func (s *Store) write(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, name+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, name))
}

func (s *Store) SaveRules(r model.RuleSet) error {
	s.Rules = r
	return s.write("rules.json", s.Rules)
}

func (s *Store) AppendAlert(a model.Alert) error {
	s.Alerts = append(s.Alerts, a)
	return s.write("alerts.json", s.Alerts)
}

func (s *Store) SaveIncidents() error {
	return s.write("incidents.json", s.Incidents)
}

func (s *Store) AppendSuppression(sup model.Suppression) error {
	s.Suppressions = append(s.Suppressions, sup)
	return s.write("suppressions.json", s.Suppressions)
}

func (s *Store) SaveSuppressions() error {
	return s.write("suppressions.json", s.Suppressions)
}

// AppendCause 注册一个原因；按 ID 去重由调用方保证（重复观察不新增原因）。
func (s *Store) AppendCause(c *model.Cause) error {
	s.Causes = append(s.Causes, c)
	return s.write("causes.json", s.Causes)
}

func (s *Store) SaveCauses() error {
	return s.write("causes.json", s.Causes)
}

func (s *Store) FindCause(id string) *model.Cause {
	for _, c := range s.Causes {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (s *Store) FindCauseByIncident(incidentID string) *model.Cause {
	for _, c := range s.Causes {
		if c.IncidentID == incidentID {
			return c
		}
	}
	return nil
}

// AppendExplanation 追加一条通知决定解释，Seq 单调递增，只增不改。
func (s *Store) AppendExplanation(x model.Explanation) error {
	x.Seq = len(s.Explanations) + 1
	s.Explanations = append(s.Explanations, x)
	return s.write("explanations.json", s.Explanations)
}

// CurrentExplanation 返回某告警当前最新的一条解释。
func (s *Store) CurrentExplanation(alertID string) *model.Explanation {
	for i := len(s.Explanations) - 1; i >= 0; i-- {
		if s.Explanations[i].AlertID == alertID {
			return &s.Explanations[i]
		}
	}
	return nil
}

// AppendNotification 把通知写入本地记录；DedupKey 已存在时跳过，
// 返回是否真正新增，保证重复重放不产生多份通知。
func (s *Store) AppendNotification(n model.Notification) (bool, error) {
	for _, existing := range s.Notifications {
		if existing.DedupKey == n.DedupKey {
			return false, nil
		}
	}
	s.Notifications = append(s.Notifications, n)
	return true, s.write("notifications.json", s.Notifications)
}

func (s *Store) HasAlert(id string) bool {
	return s.FindAlert(id) != nil
}

func (s *Store) FindAlert(id string) *model.Alert {
	for i := range s.Alerts {
		if s.Alerts[i].ID == id {
			return &s.Alerts[i]
		}
	}
	return nil
}

// FindSuppression 返回指向切片元素的指针，调用方修改后需 SaveSuppressions。
func (s *Store) FindSuppression(alertID string) *model.Suppression {
	for i := range s.Suppressions {
		if s.Suppressions[i].AlertID == alertID {
			return &s.Suppressions[i]
		}
	}
	return nil
}

// FindSuppressionBy 按告警与父事件定位一条抑制（同一告警可有多个独立原因）。
func (s *Store) FindSuppressionBy(alertID, parentIncidentID string) *model.Suppression {
	for i := range s.Suppressions {
		if s.Suppressions[i].AlertID == alertID &&
			s.Suppressions[i].ParentIncidentID == parentIncidentID {
			return &s.Suppressions[i]
		}
	}
	return nil
}

// SuppressionsFor 返回某告警当前处于活动状态的全部抑制。
func (s *Store) SuppressionsFor(alertID string) []model.Suppression {
	var out []model.Suppression
	for _, sup := range s.Suppressions {
		if sup.AlertID == alertID && sup.Status == model.SuppressionActive {
			out = append(out, sup)
		}
	}
	return out
}

func (s *Store) ActiveIncident(fingerprint string) *model.Incident {
	for _, inc := range s.Incidents {
		if inc.Fingerprint == fingerprint && inc.Status == model.IncidentActive {
			return inc
		}
	}
	return nil
}

func (s *Store) ActiveIncidentBySource(source string) *model.Incident {
	for _, inc := range s.Incidents {
		if inc.Source == source && inc.Status == model.IncidentActive {
			return inc
		}
	}
	return nil
}

func (s *Store) Dir() string { return s.dir }
