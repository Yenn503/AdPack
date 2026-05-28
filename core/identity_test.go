package core

import (
	"testing"
)

func TestResolveSessionRef(t *testing.T) {
	tests := []struct {
		name           string
		sessionUser    string
		fallbackDomain string
		wantRef        HostRef
		wantOk         bool
	}{
		{
			name:           "qualified session resolves correctly",
			sessionUser:    `sevenkingdoms.local\KINGSLANDING$`,
			fallbackDomain: "sevenkingdoms.local",
			wantRef:        HostRef{Name: "KINGSLANDING", Domain: "SEVENKINGDOMS.LOCAL"},
			wantOk:         true,
		},
		{
			name:           "bare session resolves with fallback domain",
			sessionUser:    `WINTERFELL$`,
			fallbackDomain: "north.sevenkingdoms.local",
			wantRef:        HostRef{Name: "WINTERFELL", Domain: "NORTH.SEVENKINGDOMS.LOCAL"},
			wantOk:         true,
		},
		{
			name:           "non-machine session user returns false",
			sessionUser:    `sevenkingdoms.local\Administrator`,
			fallbackDomain: "sevenkingdoms.local",
			wantRef:        HostRef{},
			wantOk:         false,
		},
		{
			name:           "empty username returns false",
			sessionUser:    "",
			fallbackDomain: "",
			wantRef:        HostRef{},
			wantOk:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, ok := ResolveSessionRef(tt.sessionUser, tt.fallbackDomain)

			if ok != tt.wantOk {
				t.Fatalf("ResolveSessionRef ok=%v, want %v", ok, tt.wantOk)
			}

			if ok && ref != tt.wantRef {
				t.Errorf("ResolveSessionRef = %+v, want %+v", ref, tt.wantRef)
			}
		})
	}
}
