package modules

import (
	"regexp"
	"strings"
)

var (
	DomainUserRe   = regexp.MustCompile(`([A-Za-z0-9._-]+)\\([A-Za-z0-9.$_-]+)`)
	GPOGUIDRe      = regexp.MustCompile(`\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}`)
	ComputerBareRe = regexp.MustCompile(`([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\$`)
)

// IsNoiseLine returns true for table-drawing or empty lines that every nxc
// parser should skip.
func IsNoiseLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	return strings.HasPrefix(line, "---") ||
		strings.HasPrefix(line, "|")
}
