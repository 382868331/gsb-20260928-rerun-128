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
	Explanations  []*model.Explanation
	Decisions     []model.DecisionState
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
	if err := read("explanations.json", &s.Explanations); err != nil {
		return fmt.Errorf("load explanations: %w", err)
	}
	if err := read("decisions.json", &s.Decisions); err != nil {
		return fmt.Errorf("load decisions: %w", err)
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

func (s *Store) SaveExplanations() error {
	return s.write("explanations.json", s.Explanations)
}

func (s *Store) SaveDecisions() error {
	return s.write("decisions.json", s.Decisions)
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

func (s *Store) ActiveIncident(fingerprint string) *model.Incident {
	for _, inc := range s.Incidents {
		if inc.Fingerprint == fingerprint && inc.Status == model.IncidentActive {
			return inc
		}
	}
	return nil
}

// LatestIncident 返回某指纹最新的一个事件（含 suppressed/resolved）。
func (s *Store) LatestIncident(fingerprint string) *model.Incident {
	var latest *model.Incident
	for _, inc := range s.Incidents {
		if inc.Fingerprint == fingerprint && (latest == nil || inc.Epoch >= latest.Epoch) {
			latest = inc
		}
	}
	return latest
}

func (s *Store) ActiveIncidentBySource(source string) *model.Incident {
	for _, inc := range s.Incidents {
		if inc.Source == source && inc.Status == model.IncidentActive {
			return inc
		}
	}
	return nil
}

// ExplanationsFor 返回某子告警身份的全部原因解释（含已撤回的，供追溯）。
func (s *Store) ExplanationsFor(subjectFP string) []*model.Explanation {
	var out []*model.Explanation
	for _, x := range s.Explanations {
		if x.AlertFingerprint == subjectFP {
			out = append(out, x)
		}
	}
	return out
}

// FindExplanation 按 子身份+父源 找解释；同一对身份只保留一条解释，
// 重复观察不会产生虚假的新原因。
func (s *Store) FindExplanation(subjectFP, parentSource string) *model.Explanation {
	var withdrawn *model.Explanation
	for _, x := range s.Explanations {
		if x.AlertFingerprint != subjectFP || x.ParentSource != parentSource {
			continue
		}
		if x.Active() {
			return x
		}
		if withdrawn == nil {
			withdrawn = x
		}
	}
	return withdrawn
}

func (s *Store) ActiveExplanation(subjectFP, parentSource string) *model.Explanation {
	if x := s.FindExplanation(subjectFP, parentSource); x != nil && x.Active() {
		return x
	}
	return nil
}

// ActiveConfirmedParents 返回当前仍以 confirmed 状态抑制该子身份的父源集合。
func (s *Store) ActiveConfirmedParents(subjectFP string) map[string]bool {
	m := map[string]bool{}
	for _, x := range s.Explanations {
		if x.AlertFingerprint == subjectFP && x.State == model.ExplConfirmed {
			if s.ParentIncidentActive(x.ParentIncidentID) {
				m[x.ParentSource] = true
			}
		}
	}
	return m
}

// ParentIncidentActive 报告某父事件当前是否仍活动。
func (s *Store) ParentIncidentActive(id string) bool {
	for _, inc := range s.Incidents {
		if inc.ID == id {
			return inc.Status == model.IncidentActive
		}
	}
	return false
}

// DecisionForFP 按子指纹找决定状态（主体 ID 在直接抑制时为首条告警 ID，
// 迟到吸收时为子事件 ID；这里为识别重复观察额外按指纹索引）。
func (s *Store) DecisionForFP(fp string) *model.DecisionState {
	for i := range s.Decisions {
		if s.Decisions[i].Fingerprint == fp {
			return &s.Decisions[i]
		}
	}
	return nil
}

func (s *Store) Dir() string { return s.dir }
