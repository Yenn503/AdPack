package tools

import (
	"context"
	"testing"
)

func TestMiniPlasma_Name(t *testing.T) {
	if MiniPlasma.Name() != "MiniPlasma" {
		t.Errorf("expected MiniPlasma, got %s", MiniPlasma.Name())
	}
}

func TestMiniPlasma_Available(t *testing.T) {
	_ = MiniPlasma.Available()
}

func TestMiniPlasma_Validate(t *testing.T) {
	err := MiniPlasma.Validate()
	if err == nil && !MiniPlasma.Available() {
		t.Error("expected error when MiniPlasma not available")
	}
}

func TestMiniPlasma_Capabilities(t *testing.T) {
	caps := MiniPlasma.Capabilities()
	found := false
	for _, c := range caps {
		if c == CapPrivEsc {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CapPrivEsc capability")
	}
}

func TestMiniPlasma_RunStream(t *testing.T) {
	ch, err := MiniPlasma.RunStream(context.Background(), ExecutionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	evt, ok := <-ch
	if !ok {
		t.Fatal("expected event from channel")
	}
	if !MiniPlasma.Available() {
		if evt.Status != StatusFailed {
			t.Error("expected StatusFailed when tool unavailable")
		}
	}
}
