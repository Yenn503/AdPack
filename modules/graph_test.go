package modules

import (
	"context"
	"fmt"
	"testing"

	"adpack/core"
)

var errTest = fmt.Errorf("fake provider error")

type fakeProvider struct {
	computers []core.Computer
	gpos      []core.GPO
	adcs      []core.ADCSTemplate
	err       error
}

func (f *fakeProvider) EnumerateComputers(context.Context) ([]core.Computer, error) {
	return f.computers, f.err
}
func (f *fakeProvider) EnumerateGPOs(context.Context) ([]core.GPO, error) {
	return f.gpos, f.err
}
func (f *fakeProvider) EnumerateADCSTemplates(context.Context) ([]core.ADCSTemplate, error) {
	return f.adcs, f.err
}
func (f *fakeProvider) EnumerateSessions(context.Context) ([]core.Session, error) {
	return nil, f.err
}
func (f *fakeProvider) EnumerateDelegation(context.Context) ([]core.PrivilegeEdge, error) {
	return nil, f.err
}

func TestRunGraphAnalysis_EmptyProvider(t *testing.T) {
	p := &fakeProvider{}
	result := RunGraphAnalysis(context.Background(), p)
	if !result.Success {
		t.Error("expected success with empty provider")
	}
	if len(result.Computers)+len(result.GPOs)+len(result.ADCS) != 0 {
		t.Error("expected no entities from empty provider")
	}
}

func TestRunGraphAnalysis_Computers(t *testing.T) {
	p := &fakeProvider{
		computers: []core.Computer{
			{Name: "DC01", Domain: "sevenkingdoms.local", OperatingSystem: "Windows Server 2022", IsDC: true},
			{Name: "SRV02", Domain: "sevenkingdoms.local", OperatingSystem: "Windows Server 2022"},
		},
	}
	result := RunGraphAnalysis(context.Background(), p)

	if len(result.Computers) != 2 {
		t.Fatalf("got %d computers, want 2", len(result.Computers))
	}
	if len(result.Evidence) != 2 {
		t.Fatalf("got %d evidence entries, want 2", len(result.Evidence))
	}

	for _, ev := range result.Evidence {
		if ev.Type != core.EvComputerEnumerated {
			t.Errorf("expected EvComputerEnumerated, got %s", ev.Type)
		}
	}

	if result.Evidence[0].Confidence != 0.95 {
		t.Errorf("DC confidence: got %f, want 0.95", result.Evidence[0].Confidence)
	}
	if result.Evidence[1].Confidence != 0.85 {
		t.Errorf("non-DC confidence: got %f, want 0.85", result.Evidence[1].Confidence)
	}
}

func TestRunGraphAnalysis_GPOs(t *testing.T) {
	p := &fakeProvider{
		gpos: []core.GPO{
			{Name: "Default Domain Policy", GUID: "{31B2F340-016D-11D2-945F-00C04FB984F9}", Domain: "sevenkingdoms.local"},
			{Name: "No GUID GPO", Domain: "sevenkingdoms.local"},
		},
	}
	result := RunGraphAnalysis(context.Background(), p)

	if len(result.GPOs) != 2 {
		t.Fatalf("got %d GPOs, want 2", len(result.GPOs))
	}

	for _, ev := range result.Evidence {
		if ev.Type != core.EvGPOEnumerated {
			t.Errorf("expected EvGPOEnumerated, got %s", ev.Type)
		}
	}

	if result.Evidence[0].Confidence != 0.9 {
		t.Errorf("GUID GPO confidence: got %f, want 0.9", result.Evidence[0].Confidence)
	}
	if result.Evidence[1].Confidence != 0.5 {
		t.Errorf("no-GUID GPO confidence: got %f, want 0.5", result.Evidence[1].Confidence)
	}
}

func TestRunGraphAnalysis_ADCS(t *testing.T) {
	p := &fakeProvider{
		adcs: []core.ADCSTemplate{
			{Name: "VulnTemplate", Domain: "sevenkingdoms.local", Vuln: "ESC1"},
			{Name: "SafeTemplate", Domain: "sevenkingdoms.local"},
		},
	}
	result := RunGraphAnalysis(context.Background(), p)

	if len(result.ADCS) != 2 {
		t.Fatalf("got %d templates, want 2", len(result.ADCS))
	}

	for _, ev := range result.Evidence {
		if ev.Type != core.EvADCSEnumerated {
			t.Errorf("expected EvADCSEnumerated, got %s", ev.Type)
		}
	}

	if result.Evidence[0].Confidence != 0.9 {
		t.Errorf("ESC template confidence: got %f, want 0.9", result.Evidence[0].Confidence)
	}
	if result.Evidence[1].Confidence != 0.5 {
		t.Errorf("safe template confidence: got %f, want 0.5", result.Evidence[1].Confidence)
	}
}

func TestRunGraphAnalysis_ProviderError(t *testing.T) {
	p := &fakeProvider{err: errTest}
	result := RunGraphAnalysis(context.Background(), p)
	if !result.Success {
		t.Error("expected Success=true even when provider fails (non-fatal)")
	}
	if len(result.Computers)+len(result.GPOs)+len(result.ADCS) != 0 {
		t.Error("expected no entities when provider errors")
	}
}
