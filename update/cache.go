package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const cacheTTL = 24 * time.Hour

type cache struct {
	LatestVersion   string    `json:"latest_version"`
	CheckedAt       time.Time `json:"checked_at"`
	NotifiedAt      time.Time `json:"notified_at"`
	NotifiedVersion string    `json:"notified_version"`
}

func (c *cache) isCheckFresh() bool {
	return time.Since(c.CheckedAt) < cacheTTL
}

func (c *cache) isNotifyFresh(version string) bool {
	return c.NotifiedVersion == version && time.Since(c.NotifiedAt) < cacheTTL
}

func cachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "ghasec", "update.json")
}

func readCache(path string) (*cache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var c cache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func writeCache(path string, c *cache) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
