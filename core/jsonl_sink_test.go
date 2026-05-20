package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONLSink_Emit(t *testing.T) {
	var buf strings.Builder
	sink := NewJSONLSink(&buf)

	ts := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	sink.Emit(ProviderEvent{
		Method: "EnumerateComputers", Transport: "ldap",
		Target: "192.168.57.10", Fallback: false,
		DurationMS: 1234, StdoutBytes: 42, StderrBytes: 0,
		EntityCount: 8, Error: "",
		Timestamp: ts,
		Stdout:    "CN=DC01,CN=Computers,DC=sevenkingdoms,DC=local",
		Stderr:    "",
	})

	sink.Emit(ProviderEvent{
		Method: "EnumerateGPOs", Transport: "smb+gpolocal",
		Target: "192.168.57.10", Fallback: true,
		DurationMS: 5678, StdoutBytes: 10, StderrBytes: 5,
		EntityCount: 3, Error: "",
		Timestamp: ts,
		Stdout:    "GPO: Test",
		Stderr:    "warn",
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d", len(lines))
	}

	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is not valid JSON: %q", i, line)
		}
		var decoded ProviderEvent
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("line %d unmarshal error: %v", i, err)
		}
	}

	// Verify the first event has inline stdout
	first := lines[0]
	if !strings.Contains(first, "CN=DC01,CN=Computers,DC=sevenkingdoms,DC=local") {
		t.Errorf("first event missing inline stdout: %s", first)
	}

	// Verify the second event has fallback=true
	var second ProviderEvent
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if !second.Fallback {
		t.Errorf("expected fallback=true on second event")
	}
	if second.DurationMS != 5678 {
		t.Errorf("expected DurationMS=5678, got %d", second.DurationMS)
	}
}

func TestJSONLSink_MarshalRoundTrip(t *testing.T) {
	// ProviderEvent values must survive marshal/unmarshal without data loss
	// for non-string fields (strings are inherently lossy around encoding).
	ev := ProviderEvent{
		Method: "EnumerateComputers", Transport: "ldap",
		Target: "192.168.57.10", Fallback: true,
		DurationMS: 999, StdoutBytes: 4, StderrBytes: 2,
		EntityCount: 5,
		Error:       "connection refused",
		Timestamp:   time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC),
		Stdout:      "data",
		Stderr:      "err",
	}

	var buf strings.Builder
	sink := NewJSONLSink(&buf)
	sink.Emit(ev)

	var got ProviderEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	cases := []struct {
		name string
		want interface{}
		got  interface{}
	}{
		{"Method", ev.Method, got.Method},
		{"Transport", ev.Transport, got.Transport},
		{"Target", ev.Target, got.Target},
		{"Fallback", ev.Fallback, got.Fallback},
		{"DurationMS", ev.DurationMS, got.DurationMS},
		{"StdoutBytes", ev.StdoutBytes, got.StdoutBytes},
		{"StderrBytes", ev.StderrBytes, got.StderrBytes},
		{"EntityCount", ev.EntityCount, got.EntityCount},
		{"Error", ev.Error, got.Error},
		{"Stdout", ev.Stdout, got.Stdout},
		{"Stderr", ev.Stderr, got.Stderr},
	}
	for _, c := range cases {
		if c.want != c.got {
			t.Errorf("%s: want %v, got %v", c.name, c.want, c.got)
		}
	}
}
