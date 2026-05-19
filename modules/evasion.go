package modules

import (
	"fmt"
	"strings"
)

type EvasionProfile struct {
	Name string `json:"name" yaml:"name"`

	// AMSI bypass method: "patch", "registry", "reflection", "hardware", ""
	AmsiBypass string `json:"amsi_bypass" yaml:"amsi_bypass"`

	// ETW patching
	EtwPatch bool `json:"etw_patch" yaml:"etw_patch"`

	// Syscall method: "hells_gate", "halos_gate", "tartarus_gate",
	// "freshycalls", "recycledgate", "hw_breakpoint", "syswhispers4", "indirect", ""
	SyscallMethod string `json:"syscall_method" yaml:"syscall_method"`

	// Sleep masking: "ekko", "gargoyle", "stack_spoof", ""
	SleepMask string `json:"sleep_mask" yaml:"sleep_mask"`

	// Injection technique: "spawn", "hollow", "apc_early_bird", "thread_hijack", "veh"
	InjectionTech string `json:"injection_tech" yaml:"injection_tech"`

	// Delivery: "donut", "bof", "exe", "go_binary", "raw"
	DeliveryMethod string `json:"delivery_method" yaml:"delivery_method"`

	// Payload source (local path)
	PayloadSource string `json:"payload_source" yaml:"payload_source"`

	// PPID spoofing target
	PPIDSpoof string `json:"ppid_spoof" yaml:"ppid_spoof"`

	// Parent process for spawning
	ParentProcess string `json:"parent_process" yaml:"parent_process"`

	// Use direct syscalls for all Win32
	DirectSyscalls bool `json:"direct_syscalls" yaml:"direct_syscalls"`

	// Call stack spoofing
	CallStackSpoof bool `json:"call_stack_spoof" yaml:"call_stack_spoof"`

	// Description
	Description string `json:"description" yaml:"description"`
}

func (p EvasionProfile) String() string {
	var parts []string
	if p.AmsiBypass != "" {
		parts = append(parts, fmt.Sprintf("AMSI:%s", p.AmsiBypass))
	}
	if p.EtwPatch {
		parts = append(parts, "ETW:patch")
	}
	if p.SyscallMethod != "" {
		parts = append(parts, fmt.Sprintf("Syscall:%s", p.SyscallMethod))
	}
	if p.SleepMask != "" {
		parts = append(parts, fmt.Sprintf("Sleep:%s", p.SleepMask))
	}
	if p.InjectionTech != "" {
		parts = append(parts, fmt.Sprintf("Inject:%s", p.InjectionTech))
	}
	if p.DeliveryMethod != "" {
		parts = append(parts, fmt.Sprintf("Delivery:%s", p.DeliveryMethod))
	}
	if p.PPIDSpoof != "" {
		parts = append(parts, fmt.Sprintf("PPID:%s", p.PPIDSpoof))
	}
	if p.CallStackSpoof {
		parts = append(parts, "StackSpoof")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " | ")
}

var EvasionProfiles = struct {
	// Minimal: basic obfuscation, suitable for lab/non-EDR targets
	Minimal EvasionProfile

	// Standard: AMSI bypass + ETW patch + Donut delivery
	Standard EvasionProfile

	// Aggressive: full evasion stack for modern EDR (CrowdStrike, Defender, SentinelOne)
	Aggressive EvasionProfile

	// BOF-based: use Cobalt Strike/Havoc BOF for in-process execution (most evasive)
	BOFBased EvasionProfile

	// Fork: nanodump --fork process cloning
	Fork EvasionProfile

	// BYOVD: kernel-level PPL bypass via RTCore64.sys
	BYOVD EvasionProfile

	// ColdWer: freeze EDR via WerFaultSecure then dump WSASS
	ColdWer EvasionProfile

	// UnDefend: kill Defender then dump LSASS
	UnDefend EvasionProfile

	// BlueHammer: leak SAM via Defender RPC
	BlueHammer EvasionProfile

	// Custom template (fill in fields)
	Custom EvasionProfile
}{
	Minimal: EvasionProfile{
		Name:           "minimal",
		AmsiBypass:     "reflection",
		DeliveryMethod: "donut",
		PayloadSource:  "go-mimikatz.bin",
		Description:    "Basic evasion for lab environments without heavy EDR",
	},
	Standard: EvasionProfile{
		Name:           "standard",
		AmsiBypass:     "patch",
		EtwPatch:       true,
		SyscallMethod:  "indirect",
		DeliveryMethod: "donut",
		PayloadSource:  "go-mimikatz.bin",
		InjectionTech:  "spawn",
		ParentProcess:  "explorer.exe",
		Description:    "Standard evasion for typical enterprise with Defender",
	},
	Aggressive: EvasionProfile{
		Name:           "aggressive",
		AmsiBypass:     "hardware",
		EtwPatch:       true,
		SyscallMethod:  "recycledgate",
		SleepMask:      "ekko",
		DeliveryMethod: "go_binary",
		PayloadSource:  "go-mimikatz",
		InjectionTech:  "apc_early_bird",
		PPIDSpoof:      "explorer.exe",
		ParentProcess:  "notepad.exe",
		CallStackSpoof: true,
		DirectSyscalls: true,
		Description:    "Full evasion for mature EDR environments (CrowdStrike/SentinelOne)",
	},
	BOFBased: EvasionProfile{
		Name:           "bof",
		AmsiBypass:     "patch",
		EtwPatch:       true,
		DeliveryMethod: "bof",
		PayloadSource:  "nanodump.o",
		InjectionTech:  "bof_inline",
		Description:    "BOF-based in-process execution via C2 (most evasive, requires C2)",
	},
	Fork: EvasionProfile{
		Name:           "fork",
		DeliveryMethod: "bof",
		PayloadSource:  "nanodump",
		InjectionTech:  "fork",
		Description:    "Clone LSASS via nanodump --fork, dump the clone. Avoids direct PROCESS_VM_READ to LSASS.",
	},
	BYOVD: EvasionProfile{
		Name:           "byovd",
		DeliveryMethod: "exe",
		PayloadSource:  "RTCore64.sys + dump-tool",
		InjectionTech:  "kernel_ppl_bypass",
		Description:    "Load RTCore64.sys (legitimately signed) to patch LSASS PPL via kernel r/w, then dump freely.",
	},
	ColdWer: EvasionProfile{
		Name:           "coldwer",
		DeliveryMethod: "exe",
		PayloadSource:  "EDR-Freeze.exe + WSASS.exe",
		InjectionTech:  "userland_freeze",
		Description:    "Freeze EDR via WerFaultSecure PPL bypass, then dump LSASS via WSASS. Detected by Defender since Oct 2025.",
	},
	UnDefend: EvasionProfile{
		Name:           "undefend",
		DeliveryMethod: "exe",
		PayloadSource:  "UnDefend.exe + nanodump.exe",
		InjectionTech:  "fork",
		Description:    "Kill Defender via UnDefend aggressive mode, then dump LSASS via nanodump --fork",
	},
	BlueHammer: EvasionProfile{
		Name:           "bluehammer",
		DeliveryMethod: "exe",
		PayloadSource:  "FunnyApp.exe",
		InjectionTech:  "rpc_exploit",
		Description:    "Exploit Defender RPC interface to leak SAM hive via VSS snapshot",
	},
	Custom: EvasionProfile{
		Name: "custom",
		Description: "User-defined evasion profile. Set fields individually.",
	},
}

func LookupProfile(name string) (EvasionProfile, bool) {
	switch name {
	case "minimal":
		return EvasionProfiles.Minimal, true
	case "standard":
		return EvasionProfiles.Standard, true
	case "aggressive":
		return EvasionProfiles.Aggressive, true
	case "bof":
		return EvasionProfiles.BOFBased, true
	case "fork":
		return EvasionProfiles.Fork, true
	case "byovd":
		return EvasionProfiles.BYOVD, true
	case "coldwer":
		return EvasionProfiles.ColdWer, true
	case "undefend":
		return EvasionProfiles.UnDefend, true
	case "bluehammer":
		return EvasionProfiles.BlueHammer, true
	case "custom":
		return EvasionProfiles.Custom, true
	}
	return EvasionProfile{}, false
}

func ListProfiles() []string {
	return []string{"minimal", "standard", "aggressive", "bof", "fork", "byovd", "coldwer", "undefend", "bluehammer", "custom"}
}
