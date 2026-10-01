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

	Rules        model.RuleSet
	Alerts       []model.Alert
	Incidents    []*model.Incident
	Suppressions []model.Suppression
	Reviews      []model.ReviewEntry
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
	if err := read("reviews.json", &s.Reviews); err != nil {
		return fmt.Errorf("load reviews: %w", err)
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

// AppendReview 追加一条影响审查审计记录。
func (s *Store) AppendReview(r model.ReviewEntry) error {
	s.Reviews = append(s.Reviews, r)
	return s.write("reviews.json", s.Reviews)
}

// FindAlert 按 ID 查找原始告警，找不到返回 nil。
func (s *Store) FindAlert(id string) *model.Alert {
	for i := range s.Alerts {
		if s.Alerts[i].ID == id {
			return &s.Alerts[i]
		}
	}
	return nil
}

// FindSuppression 按告警 ID 查找抑制关系，找不到返回 nil。
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

func (s *Store) ActiveIncidentBySource(source string) *model.Incident {
	for _, inc := range s.Incidents {
		if inc.Source == source && inc.Status == model.IncidentActive {
			return inc
		}
	}
	return nil
}

func (s *Store) Dir() string { return s.dir }
