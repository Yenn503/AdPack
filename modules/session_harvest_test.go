package modules

import (
	"adpack/core"
	"testing"
)

func TestParseSMBSessions(t *testing.T) {
	host := core.Host{IP: "192.168.57.10"}

	tests := []struct {
		name     string
		output   string
		want     int
		wantUser string
		wantSrc  string
	}{
		{
			name: "standard session with source IP",
			output: `[*] User: SEVENKINGDOMS\Administrator (from 192.168.57.22)
[*] User: SEVENKINGDOMS\bob (from 192.168.57.20)`,
			want:     2,
			wantUser: "SEVENKINGDOMS\\Administrator",
			wantSrc:  "192.168.57.22",
		},
		{
			name: "bare DOMAIN\\user without prefix",
			output: `north\DC02$
some noise line
north\alice`,
			want:     2,
			wantUser: "north\\DC02$",
		},
		{
			name: "deduplicates identical entries",
			output: `[*] User: SEVENKINGDOMS\Administrator (from 192.168.57.22)
[*] User: SEVENKINGDOMS\Administrator (from 192.168.57.22)`,
			want: 1,
		},
		{
			name: "traceback output with valid session",
			output: `[-] Failed to enumerate sessions on 192.168.57.22
[*] Error connecting to remote host
Traceback (most recent call last):
  File "nxc", line 1, in <module>
[*] User: SEVENKINGDOMS\Administrator`,
			want:     1,
			wantUser: "SEVENKINGDOMS\\Administrator",
		},
		{
			name:   "empty output",
			output: ``,
			want:   0,
		},
		{
			name:     "machine account with dollar sign",
			output:   `SRV02\DC02$`,
			want:     1,
			wantUser: "SRV02\\DC02$",
		},
		{
			name:     "mixed noise and valid session on same line",
			output:   `[-] Failed login for foo but active session SEVENKINGDOMS\Administrator`,
			want:     1,
			wantUser: "SEVENKINGDOMS\\Administrator",
		},
		{
			name:   "multiple users on one nxc line",
			output: `[*] Sessions: SEVENKINGDOMS\Administrator, north\alice`,
			want:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := parseSMBSessions(host, tt.output)
			if len(sessions) != tt.want {
				t.Errorf("got %d sessions, want %d", len(sessions), tt.want)
			}
			if tt.wantUser != "" && len(sessions) > 0 {
				if sessions[0].Username != tt.wantUser {
					t.Errorf("got Username=%q, want %q", sessions[0].Username, tt.wantUser)
				}
			}
			if tt.wantSrc != "" && len(sessions) > 0 {
				if sessions[0].SourceIP != tt.wantSrc {
					t.Errorf("got SourceIP=%q, want %q", sessions[0].SourceIP, tt.wantSrc)
				}
			}
		})
	}
}
