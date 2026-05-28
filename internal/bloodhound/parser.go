package bloodhound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParsedData holds all parsed BloodHound data ready for conversion.
type ParsedData struct {
	Users     []BHUser
	Groups    []BHGroup
	Computers []BHComputer
	Domains   []BHDomain

	// SIDMap maps ObjectIdentifier → principal name (DOMAIN\Name format).
	// Used by converter to look up principal names from SIDs.
	SIDMap map[string]string

	// SIDToType maps ObjectIdentifier → "User", "Group", "Computer", "Domain".
	SIDToType map[string]string
}

// ParseDirectory reads all BloodHound JSON files from a directory and parses them.
// Accepts files matching *_users.json, *_groups.json, *_computers.json, *_domains.json.
func ParseDirectory(dir string) (*ParsedData, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read bloodhound directory %s: %w", dir, err)
	}

	p := &ParsedData{
		SIDMap:    make(map[string]string),
		SIDToType: make(map[string]string),
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}

		name := strings.ToLower(entry.Name())
		switch {
		case strings.Contains(name, "_users"):
			if err := p.parseUsers(data); err != nil {
				return nil, fmt.Errorf("parse users %s: %w", path, err)
			}
		case strings.Contains(name, "_groups"):
			if err := p.parseGroups(data); err != nil {
				return nil, fmt.Errorf("parse groups %s: %w", path, err)
			}
		case strings.Contains(name, "_computers"):
			if err := p.parseComputers(data); err != nil {
				return nil, fmt.Errorf("parse computers %s: %w", path, err)
			}
		case strings.Contains(name, "_domains"):
			if err := p.parseDomains(data); err != nil {
				return nil, fmt.Errorf("parse domains %s: %w", path, err)
			}
		}
	}

	return p, nil
}

// ParseBytes parses BloodHound JSON data from raw bytes. This is useful when
// you've already collected BH data and want to parse it without filesystem I/O.
func ParseBytes(usersJSON, groupsJSON, computersJSON, domainsJSON []byte) (*ParsedData, error) {
	p := &ParsedData{
		SIDMap:    make(map[string]string),
		SIDToType: make(map[string]string),
	}

	if usersJSON != nil {
		if err := p.parseUsers(usersJSON); err != nil {
			return nil, fmt.Errorf("parse users: %w", err)
		}
	}
	if groupsJSON != nil {
		if err := p.parseGroups(groupsJSON); err != nil {
			return nil, fmt.Errorf("parse groups: %w", err)
		}
	}
	if computersJSON != nil {
		if err := p.parseComputers(computersJSON); err != nil {
			return nil, fmt.Errorf("parse computers: %w", err)
		}
	}
	if domainsJSON != nil {
		if err := p.parseDomains(domainsJSON); err != nil {
			return nil, fmt.Errorf("parse domains: %w", err)
		}
	}

	return p, nil
}

func (p *ParsedData) parseUsers(data []byte) error {
	var raw BHCollection
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, item := range raw.Data {
		var u BHUser
		if err := json.Unmarshal(item, &u); err != nil {
			return err
		}
		p.Users = append(p.Users, u)
	}
	// Build SID map
	for _, u := range p.Users {
		principal := bhNameToPrincipal(u.Properties.Name)
		p.SIDMap[u.ObjectIdentifier] = principal
		p.SIDToType[u.ObjectIdentifier] = "User"
	}
	return nil
}

func (p *ParsedData) parseGroups(data []byte) error {
	var raw BHCollection
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, item := range raw.Data {
		var g BHGroup
		if err := json.Unmarshal(item, &g); err != nil {
			return err
		}
		p.Groups = append(p.Groups, g)
	}
	for _, g := range p.Groups {
		principal := bhNameToPrincipal(g.Properties.Name)
		p.SIDMap[g.ObjectIdentifier] = principal
		p.SIDToType[g.ObjectIdentifier] = "Group"
	}
	return nil
}

func (p *ParsedData) parseComputers(data []byte) error {
	var raw BHCollection
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, item := range raw.Data {
		var c BHComputer
		if err := json.Unmarshal(item, &c); err != nil {
			return err
		}
		p.Computers = append(p.Computers, c)
	}
	for _, c := range p.Computers {
		principal := bhComputerToPrincipal(c.Properties.Name)
		p.SIDMap[c.ObjectIdentifier] = principal
		p.SIDToType[c.ObjectIdentifier] = "Computer"
	}
	return nil
}

func (p *ParsedData) parseDomains(data []byte) error {
	var raw BHCollection
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, item := range raw.Data {
		var d BHDomain
		if err := json.Unmarshal(item, &d); err != nil {
			return err
		}
		p.Domains = append(p.Domains, d)
	}
	for _, d := range p.Domains {
		domainName := strings.ToLower(strings.TrimSuffix(d.Properties.Name, ".LOCAL"))
		p.SIDMap[d.ObjectIdentifier] = domainName
		p.SIDToType[d.ObjectIdentifier] = "Domain"
	}
	return nil
}

// bhNameToPrincipal converts "USER@DOMAIN.LOCAL" → "DOMAIN\user".
func bhNameToPrincipal(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	idx := strings.LastIndex(name, "@")
	if idx < 0 {
		return strings.ToLower(name)
	}
	userPart := strings.ToLower(name[:idx])
	domainPart := strings.ToLower(name[idx+1:])
	domainPart = strings.TrimSuffix(domainPart, ".local")
	return domainPart + "\\" + userPart
}

// bhComputerToPrincipal converts "COMPUTER.DOMAIN.LOCAL" → "DOMAIN\computer$".
func bhComputerToPrincipal(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	parts := strings.SplitN(name, ".", 2)
	if len(parts) < 2 {
		return strings.ToLower(name) + "$"
	}
	computerName := strings.ToLower(parts[0])
	domainPart := strings.ToLower(parts[1])
	domainPart = strings.TrimSuffix(domainPart, ".local")
	return domainPart + "\\" + computerName + "$"
}
