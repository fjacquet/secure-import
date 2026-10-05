package redfish

import (
	"regexp"
	"strings"
)

var msysRe = regexp.MustCompile(`^[A-Za-z]:[/\\].*?[/\\](redfish[/\\].*)$`)

// SanitizePath reverses the MSYS/Git Bash conversion of "/redfish/..." arguments
// into "C:/Program Files/Git/redfish/..." and guarantees a leading slash.
func SanitizePath(p string) string {
	if p == "" {
		return p
	}
	if m := msysRe.FindStringSubmatch(p); m != nil {
		p = "/" + strings.ReplaceAll(m[1], `\`, "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
