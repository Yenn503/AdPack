package modules

import "testing"

// Real-world AD descriptions wrap or trail the password with punctuation.
// extractSecretFromDesc must produce the *bare* password so that downstream
// authenticated tools (impacket, nxc, bloodyAD) don't fail with garbage like
// "Heartsbane)" turning every authenticated lookup into an auth-fail.
func TestExtractSecretFromDesc(t *testing.T) {
	tests := []struct {
		name   string
		desc   string
		phrase string
		want   string
	}{
		{
			name:   "GOAD-Light samwell.tarly literal",
			desc:   "Samwell Tarly (Password : Heartsbane)",
			phrase: "password",
			want:   "Heartsbane",
		},
		{
			name:   "trailing comma",
			desc:   "John's password: P@ssw0rd!,",
			phrase: "password",
			want:   "P@ssw0rd!",
		},
		{
			name:   "wrapped in single quotes",
			desc:   "svc account password: 'ServicePass1!'",
			phrase: "password",
			want:   "ServicePass1!",
		},
		{
			name:   "wrapped in double quotes inside brackets",
			desc:   `service account [pwd: "ServicePass1!"]`,
			phrase: "pwd:",
			want:   "ServicePass1!",
		},
		{
			name:   "no separator after phrase",
			desc:   "Default password Hunter2",
			phrase: "password",
			want:   "Hunter2",
		},
		{
			name:   "no phrase match",
			desc:   "Just a regular description",
			phrase: "password",
			want:   "",
		},
		{
			name:   "internal punctuation preserved",
			desc:   "Pass: P@s.s,w0rd!",
			phrase: "pass",
			want:   "P@s.s,w0rd!",
		},
		{
			name:   "trailing period",
			desc:   "Password: Hunter2.",
			phrase: "password",
			want:   "Hunter2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSecretFromDesc(tt.desc, tt.phrase)
			if got != tt.want {
				t.Errorf("extractSecretFromDesc(%q, %q)\n  got  = %q\n  want = %q",
					tt.desc, tt.phrase, got, tt.want)
			}
		})
	}
}
