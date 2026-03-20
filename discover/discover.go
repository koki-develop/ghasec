package discover

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Result holds discovered file paths grouped by type.
type Result struct {
	Workflows []string
	Actions   []string
}

// Discover returns workflow and action file paths under baseDir.
// Workflows: baseDir/.github/workflows/*.yml|yaml
// Actions: any action.yml|action.yaml found recursively, excluding .git/ and node_modules/.
// Files that appear in both sets (e.g. .github/workflows/action.yml) are kept only in Workflows.
func Discover(baseDir string) (Result, error) {
	var res Result

	// Discover workflows via glob.
	workflowSet := map[string]struct{}{}
	for _, ext := range []string{"*.yml", "*.yaml"} {
		pattern := filepath.Join(baseDir, ".github", "workflows", ext)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return Result{}, err
		}
		for _, m := range matches {
			abs, err := filepath.Abs(m)
			if err != nil {
				return Result{}, err
			}
			workflowSet[abs] = struct{}{}
		}
		res.Workflows = append(res.Workflows, matches...)
	}

	// Discover action files via recursive walk.
	err := filepath.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if name != "action.yml" && name != "action.yaml" {
			return nil
		}
		// Normalize to check if already in workflow set.
		cleanPath := path
		if !filepath.IsAbs(cleanPath) {
			var absErr error
			cleanPath, absErr = filepath.Abs(cleanPath)
			if absErr != nil {
				return fmt.Errorf("failed to resolve absolute path for %s: %w", cleanPath, absErr)
			}
		}
		if _, dup := workflowSet[cleanPath]; dup {
			return nil
		}
		// Skip paths that are inside .github/workflows/ (belt-and-suspenders).
		slashed := filepath.ToSlash(path)
		if strings.Contains(slashed, ".github/workflows/") {
			return nil
		}
		res.Actions = append(res.Actions, path)
		return nil
	})
	if err != nil {
		return Result{}, err
	}

	sort.Strings(res.Workflows)
	sort.Strings(res.Actions)

	return res, nil
}
