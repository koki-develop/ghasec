package update

import (
	"fmt"
	"strconv"
	"strings"
)

type semver struct {
	major, minor, patch int
}

func parseSemver(s string) (semver, error) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("invalid semver: %q", s)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return semver{}, fmt.Errorf("invalid semver: %q", s)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return semver{}, fmt.Errorf("invalid semver: %q", s)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil || patch < 0 {
		return semver{}, fmt.Errorf("invalid semver: %q", s)
	}
	return semver{major, minor, patch}, nil
}

func (v semver) lessThan(other semver) bool {
	if v.major != other.major {
		return v.major < other.major
	}
	if v.minor != other.minor {
		return v.minor < other.minor
	}
	return v.patch < other.patch
}

func (v semver) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}
