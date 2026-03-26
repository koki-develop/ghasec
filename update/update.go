package update

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/koki-develop/ghasec/github"
)

const (
	repoOwner = "koki-develop"
	repoName  = "ghasec"
)

// Result holds the version information when an update is available.
type Result struct {
	CurrentVersion string
	NewVersion     string
}

// Check queries for the latest release and returns a Result if a newer version
// is available and the notification has not been recently shown. Returns nil
// when no notification is needed or on any error (errors are silently ignored).
func Check(ctx context.Context, client *github.Client, currentVersion string) *Result {
	return check(ctx, client, currentVersion, cachePath())
}

func check(ctx context.Context, client *github.Client, currentVersion, cpath string) *Result {
	if cpath == "" {
		return nil
	}
	c, err := readCache(cpath)
	if err != nil {
		_ = os.Remove(cpath)
	}
	if c == nil {
		c = &cache{}
	}

	latestTag := c.LatestVersion
	if !c.isCheckFresh() {
		tag, err := client.LatestRelease(ctx, repoOwner, repoName)
		if err != nil {
			return nil
		}
		latestSV, err := parseSemver(tag)
		if err != nil {
			return nil
		}
		latestTag = latestSV.String()
		c.LatestVersion = latestTag
		c.CheckedAt = time.Now().UTC()
		_ = writeCache(cpath, c)
	}

	if latestTag == "" {
		return nil
	}

	latestSV, err := parseSemver(latestTag)
	if err != nil {
		return nil
	}

	currentDisplay := currentVersion
	currentSV, currentErr := parseSemver(currentVersion)
	if currentErr == nil {
		currentDisplay = currentSV.String()
		if !currentSV.lessThan(latestSV) {
			return nil
		}
	}
	// If currentErr != nil, treat current as older (always notify)

	if c.isNotifyFresh(latestSV.String()) {
		return nil
	}

	return &Result{
		CurrentVersion: currentDisplay,
		NewVersion:     latestSV.String(),
	}
}

// MarkNotified updates the cache to record that a notification was shown for
// the given version. Errors are silently ignored.
func MarkNotified(version string) {
	markNotified(version, cachePath())
}

func markNotified(version, cpath string) {
	if cpath == "" {
		return
	}
	c, err := readCache(cpath)
	if err != nil {
		_ = os.Remove(cpath)
	}
	if c == nil {
		c = &cache{}
	}
	c.NotifiedAt = time.Now().UTC()
	c.NotifiedVersion = strings.TrimPrefix(version, "v")
	_ = writeCache(cpath, c)
}
