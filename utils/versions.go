package utils

// ToolVersion specifies minimum required versions for external dependencies.
// These are checked by validate tools --strict.
type ToolVersion struct {
	Name    string
	MinVer  string
	Flag    string // version flag, e.g. "--version"
	Install string // install instructions
}

// RequiredTools lists all external tools adpack depends on with minimum versions.
var RequiredTools = []ToolVersion{
	{Name: "netexec", MinVer: "1.5.0", Flag: "--version", Install: "pipx install netexec"},
	{Name: "nxc", MinVer: "1.5.0", Flag: "--version", Install: "pipx install netexec"},
	{Name: "certipy", MinVer: "4.8.0", Flag: "--version", Install: "pipx install certipy-ad"},
	{Name: "impacket-secretsdump", MinVer: "0.12.0", Flag: "--version", Install: "pipx install impacket"},
	{Name: "impacket-getTGT", MinVer: "0.12.0", Flag: "--version", Install: "pipx install impacket"},
	{Name: "impacket-ticketer", MinVer: "0.12.0", Flag: "--version", Install: "pipx install impacket"},
	{Name: "impacket-dpapi", MinVer: "0.12.0", Flag: "--version", Install: "pipx install impacket"},
	{Name: "bloodhound-python", MinVer: "1.7.0", Flag: "--version", Install: "pipx install bloodhound"},
	{Name: "hashcat", MinVer: "6.2.0", Flag: "--version", Install: "apt-get install hashcat"},
	{Name: "dploot", MinVer: "1.0.0", Flag: "--version", Install: "pipx install dploot"},
	{Name: "pypykatz", MinVer: "0.6.0", Flag: "--version", Install: "pipx install pypykatz"},
	{Name: "donut", MinVer: "1.0.0", Flag: "--version", Install: "build from source: https://github.com/TheWover/donut"},
}

// OptionalTools are tools that enhance functionality but aren't required.
var OptionalTools = []ToolVersion{
	{Name: "klist", MinVer: "", Flag: "", Install: "apt-get install krb5-user"},
	{Name: "ldapsearch", MinVer: "", Flag: "", Install: "apt-get install ldap-utils"},
}

// WindowsBinaries are exe files expected in the exe/ directory.
var WindowsBinaries = []struct{ Name, Desc string }{
	{Name: "nanodump.exe", Desc: "LSASS memory dumper"},
	{Name: "go-mimikatz.exe", Desc: "Credential extraction (optional, falls back to nanodump)"},
	{Name: "PrintSpoofer64.exe", Desc: "SeImpersonate privilege escalation"},
	{Name: "UnDefend.exe", Desc: "Defender neutralisation (optional)"},
}
