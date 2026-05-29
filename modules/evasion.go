package modules

type EvasionProfile struct {
	Name           string `json:"name" yaml:"name"`
	DeliveryMethod string `json:"delivery_method" yaml:"delivery_method"`
	PayloadSource  string `json:"payload_source" yaml:"payload_source"`
	Description    string `json:"description" yaml:"description"`
	PreCondition   string `json:"pre_condition" yaml:"pre_condition"`
}

var EvasionProfiles = struct {
	Standard      EvasionProfile
	Bypass        EvasionProfile
	UnDefend      EvasionProfile
	PPLShade      EvasionProfile
	PhantomKiller EvasionProfile
	Custom        EvasionProfile
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
		Description:    "Standard profile with pre-flight Defender neutralisation via native commands",
		PreCondition:   "native",
	},
	UnDefend: EvasionProfile{
		Name:           "native",
		DeliveryMethod: "exe",
		PayloadSource:  "nanodump",
		Description:    "Defender kill via native reg add/sc stop/taskkill, then dump LSASS with nanodump",
		PreCondition:   "native",
	},
	PPLShade: EvasionProfile{
		Name:           "pplshade",
		DeliveryMethod: "exe",
		PayloadSource:  "nanodump",
		Description:    "Upload PPLShade.exe + LECOMAx64.sys driver, strip LSASS PPL, dump with nanodump",
		PreCondition:   "native",
	},
	PhantomKiller: EvasionProfile{
		Name:           "phantomkiller",
		DeliveryMethod: "exe",
		PayloadSource:  "nanodump",
		Description:    "Upload PhantomKiller.sys + PhantomKiller.exe, load signed Lenovo driver, kill EDR, dump with nanodump",
		PreCondition:   "native",
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
	case "native":
		return EvasionProfiles.UnDefend, true
	case "pplshade":
		return EvasionProfiles.PPLShade, true
	case "phantomkiller":
		return EvasionProfiles.PhantomKiller, true
	case "custom":
		return EvasionProfiles.Custom, true
	}
	return EvasionProfile{}, false
}

func ListProfiles() []string {
	return []string{"standard", "bypass", "native", "pplshade", "phantomkiller", "custom"}
}

func BaseProfileFor(name string) string {
	switch name {
	case "standard":
		return "standard"
	case "bypass":
		return "bypass"
	case "native":
		return "native"
	case "pplshade":
		return "pplshade"
	case "phantomkiller":
		return "phantomkiller"
	case "custom":
		return "custom"
	}
	return "standard"
}

func IsBypassProfile(name string) bool {
	return BaseProfileFor(name) == "bypass"
}
