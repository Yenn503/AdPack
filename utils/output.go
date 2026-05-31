package utils

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

func PhaseHeader(num int, name, rationale string) {
	title := PhaseTitle.Render(fmt.Sprintf("%s  PHASE %02d · %s", PhaseEmoji(name), num, strings.ToUpper(name)))
	body := title
	if strings.TrimSpace(rationale) != "" {
		body = lipgloss.JoinVertical(lipgloss.Left, title, MutedStyle.Render(rationale))
	}
	fmt.Println(PhaseBox.Render(body))
}

func PhaseEmoji(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "discovery":
		return "🛰️"
	case "enumeration":
		return "📇"
	case "credential_acq":
		return "🔑"
	case "validation":
		return "✅"
	case "session_harvest":
		return "🪪"
	case "graph_analysis":
		return "🕸️"
	case "privesc":
		return "🚀"
	case "lateral":
		return "↔️"
	case "persistence":
		return "⚓"
	case "impact":
		return "💥"
	case "hybrid_bridge":
		return "🌉"
	case "cloud_initial_access":
		return "🎣"
	case "cloud_enum":
		return "☁️"
	case "cloud_cred_acq":
		return "🔐"
	case "cloud_privesc":
		return "⬆️"
	case "cloud_pillage":
		return "📦"
	default:
		return "◆"
	}
}

func Section(icon, title, detail string) {
	line := fmt.Sprintf("%s  %s", icon, lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary).Render(title))
	if detail != "" {
		line += "  " + MutedStyle.Render(detail)
	}
	fmt.Printf("\n  %s\n", line)
}

func Attempt(icon, target, detail string) {
	fmt.Printf("    %s  %s  %s\n", icon, HostStyle.Render(target), MutedStyle.Render(detail))
}

func PhaseSkipped(phase, reason, command string) {
	StepWarn(fmt.Sprintf("%s skipped: %s", phase, reason))
	if command != "" {
		StepInfo("Run manually: " + command)
	}
}

func Step(msg string) {
	fmt.Printf("  %s  %s\n", StepStyle.Render("▸"), msg)
}

func StepOk(msg string) {
	fmt.Printf("  %s  %s\n", Check, msg)
}

func StepFail(msg string) {
	fmt.Printf("  %s  %s\n", Cross, msg)
}

func StepWarn(msg string) {
	fmt.Printf("  %s  %s\n", WarnStyle.Render("⚠"), msg)
}

func StepInfo(msg string) {
	fmt.Printf("  %s  %s\n", Arrow, msg)
}

func Finding(kind, detail string) {
	fmt.Printf("    %s  %s\n", Bullet, lipgloss.NewStyle().Foreground(ColorHighlight).Render(kind)+"  "+lipgloss.NewStyle().Foreground(ColorMuted).Render(detail))
}

func FindingVal(key, val string) {
	fmt.Printf("    %s  %s  %s\n", Bullet, lipgloss.NewStyle().Foreground(ColorHighlight).Render(key), ValStyle.Render(val))
}

func EdgeDisplay(source, accessRight, target string, exploit, noise float64) {
	fmt.Printf("      %s  %s  %s  %s  %s\n",
		PathStyle.Render(source),
		Arrow,
		ValStyle.Render(accessRight),
		Arrow,
		HostStyle.Render(target),
	)
	if exploit > 0 || noise > 0 {
		fmt.Printf("      %s  exploit=%.1f  noise=%.1f\n",
			DimStyle.Render(" "),
			exploit, noise)
	}
}

func PhaseComplete(elapsed time.Duration) {
	body := fmt.Sprintf("%s  %s  %s", Check, SuccessStyle.Render("complete"), DimStyle.Render(elapsed.Round(time.Millisecond).String()))
	fmt.Println(PanelBox.Render(body))
}

func PhaseFailed(elapsed time.Duration) {
	body := fmt.Sprintf("%s  %s  %s", Cross, ErrorStyle.Render("failed"), DimStyle.Render(elapsed.Round(time.Millisecond).String()))
	fmt.Println(PanelBox.Render(body))
}

func Summary(phasesRun, hosts, users, creds, validated int) {
	bar := strings.Repeat("─", 52)
	fmt.Println(lipgloss.NewStyle().Foreground(ColorSecondary).Render("  " + bar))
	fmt.Printf("  %s  %d phases  ·  %d hosts  ·  %d users  ·  %d creds (%d validated)\n",
		InfoStyle.Render("■"),
		phasesRun, hosts, users, creds, validated)
}

func LimitReached(max int) {
	fmt.Printf("\n  %s  Limit reached (%d phases executed)\n",
		InfoStyle.Render("■"), max)
}

func AllComplete() {
	fmt.Printf("\n  %s  %s\n",
		SuccessStyle.Render("✓"),
		lipgloss.NewStyle().Foreground(ColorMuted).Render("All phases complete or blocked. Review state."))
}
