package tools

import (
	"adpack/core"
	"adpack/utils"
	"fmt"
)

type ldapTool struct{}

var LDAP = ldapTool{}

func (ldapTool) Name() string { return "ldapsearch" }
func (ldapTool) Available() bool {
	return utils.ToolAvailable("ldapsearch")
}

func (ldapTool) Query(server, baseDN, query string) utils.CmdResult {
	return utils.RunCommand("ldapsearch",
		"-x", "-H", fmt.Sprintf("ldap://%s", server),
		"-b", baseDN, query,
	)
}

func (ldapTool) EnumUsers(server, domain string) []core.User {
	r := ldapTool{}.Query(server, fmt.Sprintf("DC=%s", stringsReplace(domain, ".", ",DC=")), "(objectClass=user)")
	if !r.Success { return nil }
	_ = r
	return nil
}

func stringsReplace(s, old, new string) string {
	return stringsReplaceAll(s, old, new)
}

func stringsReplaceAll(s, old, new string) string {
	var result []byte
	for i := 0; i < len(s); i++ {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result = append(result, []byte(new)...)
			i += len(old) - 1
		} else {
			result = append(result, s[i])
		}
	}
	return string(result)
}

func (ldapTool) EnumDomainControllers(server, domain string) []core.Host {
	r := ldapTool{}.Query(server, fmt.Sprintf("DC=%s", stringsReplace(domain, ".", ",DC=")), "(userAccountControl:1.2.840.113556.1.4.803:=8192)")
	if !r.Success { return nil }
	_ = r
	return nil
}
