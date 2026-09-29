package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"alertcorr/internal/model"
)

const (
	rulesFile  = "rules.json"
	alertsFile = "raw_alerts.json"
	eventsFile = "events.json"
)

// Store 把三类身份分别持久化：规则版本、原始告警（只追加）、事件身份。
type Store struct {
	dir string
}

func New(dir string) *Store {
	return &Store{dir: dir}
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// SaveRules 保存当前生效规则版本（历史版本以切片形式保留）。
func (s *Store) SaveRules(versions []model.RuleSet) error {
	return writeJSON(s.path(rulesFile), versions)
}

func (s *Store) LoadRules() ([]model.RuleSet, error) {
	var versions []model.RuleSet
	if err := readJSON(s.path(rulesFile), &versions); err != nil {
		return nil, fmt.Errorf("load rules: %w", err)
	}
	return versions, nil
}

// AppendAlert 将一条原始告警追加到只追加日志并落盘。
func (s *Store) AppendAlert(alerts []model.Alert) error {
	return writeJSON(s.path(alertsFile), alerts)
}

func (s *Store) LoadAlerts() ([]model.Alert, error) {
	var alerts []model.Alert
	if err := readJSON(s.path(alertsFile), &alerts); err != nil {
		return nil, fmt.Errorf("load alerts: %w", err)
	}
	return alerts, nil
}

// SaveEvents 保存全部事件身份（含来源与抑制证据）。
func (s *Store) SaveEvents(events []*model.Event) error {
	return writeJSON(s.path(eventsFile), events)
}

func (s *Store) LoadEvents() ([]*model.Event, error) {
	var events []*model.Event
	if err := readJSON(s.path(eventsFile), &events); err != nil {
		return nil, fmt.Errorf("load events: %w", err)
	}
	return events, nil
}
