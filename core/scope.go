package core

import (
	"fmt"
	"net"
	"strings"
)

type Scope struct {
	allowed []*net.IPNet
	cidrs   []string
}

func NewScope(cidrs []string) (*Scope, error) {
	allowed := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR %q: %w", c, err)
		}
		allowed = append(allowed, n)
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("scope: at least one valid CIDR required")
	}
	return &Scope{allowed: allowed, cidrs: cidrs}, nil
}

func (s *Scope) Contains(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range s.allowed {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

func (s *Scope) String() string {
	if len(s.cidrs) == 0 {
		return "(empty)"
	}
	return fmt.Sprintf("Scope{%s}", strings.Join(s.cidrs, ", "))
}
