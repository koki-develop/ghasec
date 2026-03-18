package discover

import (
	"path/filepath"
)

// Discover returns workflow file paths under baseDir/.github/workflows/.
// Matches *.yml and *.yaml.
// Returns empty slice (not error) if the directory doesn't exist or no files match.
func Discover(baseDir string) ([]string, error) {
	var files []string
	for _, ext := range []string{"*.yml", "*.yaml"} {
		pattern := filepath.Join(baseDir, ".github", "workflows", ext)
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}
	return files, nil
}
