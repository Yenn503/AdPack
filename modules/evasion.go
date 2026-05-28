package modules

type EvasionProfile struct {
	Name           string `json:"name" yaml:"name"`
	DeliveryMethod string `json:"delivery_method" yaml:"delivery_method"`
	PayloadSource  string `json:"payload_source" yaml:"payload_source"`
	Description    string `json:"description" yaml:"description"`
	PreCondition   string `json:"pre_condition" yaml:"pre_condition"`
}

var EvasionProfiles = struct {
	Standard EvasionProfile
	Bypass   EvasionProfile
	Custom   EvasionProfile
}{
	Standard: EvasionProfile{
		Name:           "standard",
		DeliveryMethod: "donut",
		PayloadSource:  "go-mimikatz",
		Description:    "Standard remote execution for enterprise environments",
		PreCondition:   "",
	},
	Bypass: EvasionProfile{
		Name:           "bypass",
		DeliveryMethod: "go_binary",
		PayloadSource:  "go-mimikatz",
		Description:    "Standard profile with pre-flight Defender neutralisation",
		PreCondition:   "undefend",
	},
	Custom: EvasionProfile{
		Name:        "custom",
		Description: "User-defined evasion profile",
	},
}

func LookupProfile(name string) (EvasionProfile, bool) {
	switch name {
	case "standard":
		return EvasionProfiles.Standard, true
	case "bypass":
		return EvasionProfiles.Bypass, true
	case "custom":
		return EvasionProfiles.Custom, true
	}
	return EvasionProfile{}, false
}

func ListProfiles() []string {
	return []string{"standard", "bypass", "custom"}
}

func BaseProfileFor(name string) string {
	switch name {
	case "standard":
		return "standard"
	case "bypass":
		return "bypass"
	case "custom":
		return "custom"
	}
	return "standard"
}

// IsBypassProfile reports whether the named profile triggers a Defender/EDR
// neutralisation pre-flight in modules that gate on it (privesc, credential_acq).
func IsBypassProfile(name string) bool {
	return BaseProfileFor(name) == "bypass"
}
