package utils

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

func PhaseHeader(num int, name, rationale string) {
	bar := strings.Repeat("─", 52)
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Foreground(ColorSecondary).Render("  " + bar))
	fmt.Printf("  %s  %s\n",
		lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary).Render(fmt.Sprintf("[%d] %s", num, strings.ToUpper(name))),
		lipgloss.NewStyle().Foreground(ColorMuted).Render(rationale))
	fmt.Println(lipgloss.NewStyle().Foreground(ColorSecondary).Render("  " + bar))
	fmt.Println()
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
	fmt.Printf("  %s  %s\n", WarnStyle.Render("!"), msg)
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
	fmt.Printf("\n  %s  %s  %s\n",
		Check,
		lipgloss.NewStyle().Foreground(ColorMuted).Render("complete"),
		DimStyle.Render("· "+elapsed.Round(time.Millisecond).String()))
}

func PhaseFailed(elapsed time.Duration) {
	fmt.Printf("\n  %s  %s  %s\n",
		Cross,
		lipgloss.NewStyle().Foreground(ColorMuted).Render("failed"),
		DimStyle.Render(elapsed.Round(time.Millisecond).String()))
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
