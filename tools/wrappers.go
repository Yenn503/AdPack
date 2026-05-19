package tools

import "adpack/utils"

type Runner interface {
	Name() string
	Available() bool
}

type ToolDef struct {
	Name     string
	Binaries []string
}

func (t ToolDef) Available() bool {
	for _, b := range t.Binaries {
		if utils.ToolAvailable(b) {
			return true
		}
	}
	return false
}
