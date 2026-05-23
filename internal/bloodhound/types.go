package bloodhound

import "encoding/json"

// BHCollection wraps the top-level BloodHound JSON file format.
type BHCollection struct {
	Data []json.RawMessage `json:"data"`
}

// BHUser represents a BloodHound user object.
type BHUser struct {
	ObjectIdentifier  string      `json:"ObjectIdentifier"`
	PrimaryGroupSID   string      `json:"PrimaryGroupSID"`
	Properties        BHUserProps `json:"Properties"`
	Aces              []BHAce     `json:"Aces"`
	SPNTargets        []string    `json:"SPNTargets"`
	AllowedToDelegate []string    `json:"AllowedToDelegate"`
	HasSIDHistory     []string    `json:"HasSIDHistory"`
	IsDeleted         bool        `json:"IsDeleted"`
}

type BHUserProps struct {
	Name                    string      `json:"name"`
	Domain                  string      `json:"domain"`
	DomainSID               string      `json:"domainsid"`
	DistinguishedName       string      `json:"distinguishedname"`
	Enabled                 interface{} `json:"enabled"`
	PasswordLastSet         interface{} `json:"pwdlastset"`
	LastLogon               interface{} `json:"lastlogon"`
	SIDHistory              []string    `json:"sidhistory"`
	UnconstrainedDelegation bool        `json:"unconstraineddelegation"`
	TrustedToAuth           bool        `json:"trustedtoauth"`
	PasswordNotRequired     bool        `json:"passwordnotreqd"`
	DontRequirePreAuth      bool        `json:"dontreqpreauth"`
	Description             string      `json:"description"`
	DisplayName             string      `json:"displayname"`
	ServicePrincipalNames   []string    `json:"serviceprincipalnames"`
	Email                   string      `json:"email"`
	SAMAccountName          string      `json:"samaccountname"`
	HasSPN                  bool        `json:"hasspn"`
}

// BHGroup represents a BloodHound group object.
type BHGroup struct {
	ObjectIdentifier  string       `json:"ObjectIdentifier"`
	Properties        BHGroupProps `json:"Properties"`
	Members           []BHMember   `json:"Members"`
	Aces              []BHAce      `json:"Aces"`
	AllowedToDelegate []string     `json:"AllowedToDelegate"`
	HasSIDHistory     []string     `json:"HasSIDHistory"`
	IsDeleted         bool         `json:"IsDeleted"`
}

type BHGroupProps struct {
	Name              string      `json:"name"`
	Domain            string      `json:"domain"`
	DomainSID         string      `json:"domainsid"`
	DistinguishedName string      `json:"distinguishedname"`
	Description       string      `json:"description"`
	AdminCount        interface{} `json:"admincount"`
}

// BHMember is a member entry inside a group.
type BHMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"` // "User" or "Group"
}

// BHComputer represents a BloodHound computer object.
type BHComputer struct {
	ObjectIdentifier   string             `json:"ObjectIdentifier"`
	Properties         BHComputerProps    `json:"Properties"`
	Aces               []BHAce            `json:"Aces"`
	Sessions           BHResultCollection `json:"Sessions"`
	LocalAdmins        BHResultCollection `json:"LocalAdmins"`
	RemoteDesktopUsers BHResultCollection `json:"RemoteDesktopUsers"`
	DcomUsers          BHResultCollection `json:"DcomUsers"`
	PSRemoteUsers      BHResultCollection `json:"PSRemoteUsers"`
	AllowedToDelegate  []string           `json:"AllowedToDelegate"`
	AllowedToAct       []BHAllowedToAct   `json:"AllowedToAct"`
	HasSIDHistory      []string           `json:"HasSIDHistory"`
	IsDeleted          bool               `json:"IsDeleted"`
}

type BHComputerProps struct {
	Name                    string      `json:"name"`
	Domain                  string      `json:"domain"`
	DomainSID               string      `json:"domainsid"`
	DistinguishedName       string      `json:"distinguishedname"`
	OperatingSystem         string      `json:"operatingsystem"`
	ServicePack             string      `json:"servicepack"`
	IsDomainController      bool        `json:"isdomaincontroller"`
	Enabled                 interface{} `json:"enabled"`
	UnconstrainedDelegation bool        `json:"unconstraineddelegation"`
	TrustedToAuth           bool        `json:"trustedtoauth"`
	SAMAccountName          string      `json:"samaccountname"`
	Description             string      `json:"description"`
	ServicePrincipalNames   []string    `json:"serviceprincipalnames"`
}

// BHResultCollection wraps BloodHound result sets that have Collected/Results.
type BHResultCollection struct {
	Collected     bool              `json:"Collected"`
	FailureReason *string           `json:"FailureReason"`
	Results       []json.RawMessage `json:"Results"`
}

// BHSessionResult is an item inside a Sessions.Results array.
type BHSessionResult struct {
	UserSID    string `json:"UserSID"`
	ComputerID string `json:"ComputerID,omitempty"`
	LastSeen   string `json:"LastSeen,omitempty"`
	Weight     int    `json:"Weight,omitempty"`
}

// BHLocalAdminResult is an item inside a LocalAdmins.Results array.
type BHLocalAdminResult struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// BHAce represents an ACL entry on a BloodHound object.
type BHAce struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	IsInherited   bool   `json:"IsInherited"`
}

// BHAllowedToAct represents a resource-based constrained delegation entry.
type BHAllowedToAct struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
}

// BHDomain represents a BloodHound domain object.
type BHDomain struct {
	ObjectIdentifier string        `json:"ObjectIdentifier"`
	Properties       BHDomainProps `json:"Properties"`
	Aces             []BHAce       `json:"Aces"`
}

type BHDomainProps struct {
	Name              string `json:"name"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	SID               string `json:"sid"`
}
