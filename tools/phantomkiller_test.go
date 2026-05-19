package tools

import (
	"context"
	"testing"
)

func TestPhantomKiller_Name(t *testing.T) {
	if PhantomKiller.Name() != "PhantomKiller" {
		t.Errorf("expected PhantomKiller, got %s", PhantomKiller.Name())
	}
}

func TestPhantomKiller_Available(t *testing.T) {
	_ = PhantomKiller.Available()
}

func TestPhantomKiller_Validate(t *testing.T) {
	err := PhantomKiller.Validate()
	if err == nil && !PhantomKiller.Available() {
		t.Error("expected error when PhantomKiller not available")
	}
}

func TestPhantomKiller_Capabilities(t *testing.T) {
	caps := PhantomKiller.Capabilities()
	found := false
	for _, c := range caps {
		if c == CapEDRKill {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CapEDRKill capability")
	}
}

func TestPhantomKiller_RunStream(t *testing.T) {
	ch, err := PhantomKiller.RunStream(context.Background(), ExecutionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	evt, ok := <-ch
	if !ok {
		t.Fatal("expected event from channel")
	}
	if !PhantomKiller.Available() {
		if evt.Status != StatusFailed {
			t.Error("expected StatusFailed when tool unavailable")
		}
	}
}

func TestPhantomKiller_DefaultConfig(t *testing.T) {
	cfg := DefaultPhantomKillerConfig()
	if cfg.Binary != "PhantomKiller.exe" {
		t.Errorf("expected PhantomKiller.exe, got %s", cfg.Binary)
	}
	if cfg.Driver != "BootRepair.sys" {
		t.Errorf("expected BootRepair.sys, got %s", cfg.Driver)
	}
}

func TestPhantomKillerConfig_Mode(t *testing.T) {
	cfg := DefaultPhantomKillerConfig()
	cfg.Mode = PhantomKillerModeKill
	if cfg.Mode != PhantomKillerModeKill {
		t.Errorf("expected %s, got %s", PhantomKillerModeKill, cfg.Mode)
	}
	cfg.Mode = PhantomKillerModeLoad
	if cfg.Mode != PhantomKillerModeLoad {
		t.Errorf("expected %s, got %s", PhantomKillerModeLoad, cfg.Mode)
	}
}
