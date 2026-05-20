package core

import (
	"testing"
)

func TestHostRef_CrossObservationCollapse(t *testing.T) {
	// The core invariant: LDAP and SMB observations of the same machine
	// must produce identical HostRef values.

	tests := []struct {
		name           string
		computerName   string
		computerDomain string
		sessionUser    string
		fallbackDomain string
		wantRef        HostRef
		wantOk         bool
	}{
		{
			name:           "qualified session matches ldap computer",
			computerName:   "KINGSLANDING",
			computerDomain: "sevenkingdoms.local",
			sessionUser:    `sevenkingdoms.local\KINGSLANDING$`,
			fallbackDomain: "sevenkingdoms.local",
			wantRef:        HostRef{Name: "KINGSLANDING", Domain: "SEVENKINGDOMS.LOCAL"},
			wantOk:         true,
		},
		{
			name:           "bare session resolves with fallback domain",
			computerName:   "WINTERFELL",
			computerDomain: "north.sevenkingdoms.local",
			sessionUser:    `WINTERFELL$`,
			fallbackDomain: "north.sevenkingdoms.local",
			wantRef:        HostRef{Name: "WINTERFELL", Domain: "NORTH.SEVENKINGDOMS.LOCAL"},
			wantOk:         true,
		},
		{
			name:           "non-machine session user returns false",
			computerName:   "Administrator",
			computerDomain: "sevenkingdoms.local",
			sessionUser:    `sevenkingdoms.local\Administrator`,
			fallbackDomain: "sevenkingdoms.local",
			wantRef:        HostRef{},
			wantOk:         false,
		},
		{
			name:           "empty username returns false",
			computerName:   "",
			computerDomain: "",
			sessionUser:    "",
			fallbackDomain: "",
			wantRef:        HostRef{},
			wantOk:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ldapRef := ResolveComputerRef(tt.computerName, tt.computerDomain)
			sessionRef, ok := ResolveSessionRef(tt.sessionUser, tt.fallbackDomain)

			if ok != tt.wantOk {
				t.Fatalf("ResolveSessionRef ok=%v, want %v", ok, tt.wantOk)
			}

			if tt.wantOk {
				if ldapRef != sessionRef {
					t.Errorf("convergence failure:\n  ldapRef=%+v\n  sessionRef=%+v",
						ldapRef, sessionRef)
				}
				if sessionRef != tt.wantRef {
					t.Errorf("sessionRef=%+v, want %+v", sessionRef, tt.wantRef)
				}
			}
		})
	}
}
