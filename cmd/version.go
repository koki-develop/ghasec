package cmd

import "runtime/debug"

// version is set via ldflags at build time (e.g. by goreleaser).
// When empty, resolveVersion falls back to build info or "dev".
var version string

func resolveVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "dev"
}
