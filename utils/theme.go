package utils

import "charm.land/lipgloss/v2"

var (
	// Monochrome UI chrome
	ColorPrimary       = lipgloss.Color("#FFFFFF") // Pure white
	ColorSecondary     = lipgloss.Color("#A0A0A0") // Light gray
	ColorMuted         = lipgloss.Color("#666666") // Medium gray
	ColorHighlight     = lipgloss.Color("#E0E0E0") // Near-white
	ColorTextOnPrimary = lipgloss.Color("#1A1A1A") // Dark text on white bg

	// Semantic event colors
	ColorSuccess = lipgloss.Color("#2E7D32") // Forest Green
	ColorWarning = lipgloss.Color("#F57C00") // Amber
	ColorError   = lipgloss.Color("#C62828") // Deep Red
	ColorInfo    = lipgloss.Color("#0288D1") // Light Blue
	ColorCyan    = lipgloss.Color("#00BCD4") // Cyan accent
	ColorPurple  = lipgloss.Color("#7C4DFF") // Purple accent

	// Common Styles
	BaseStyle = lipgloss.NewStyle().Foreground(ColorHighlight)

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(ColorSecondary).
			MarginBottom(1)

	ContainerStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSecondary).
			Padding(0, 1)

	// Logging & Output Styles
	InfoStyle    = lipgloss.NewStyle().Foreground(ColorInfo).Bold(true)
	SuccessStyle = lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true)
	ErrorStyle   = lipgloss.NewStyle().Foreground(ColorError).Bold(true)
	WarningStyle = lipgloss.NewStyle().Foreground(ColorWarning).Bold(true)

	OutputBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorMuted).
			Padding(0, 1)

	BannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			MarginBottom(1).
			MarginTop(1)

	// Phase output styles
	PhaseBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSecondary).
			Padding(0, 2).
			MarginTop(1).
			MarginBottom(1)

	PhaseTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPrimary).
			Padding(0, 1)

	PhaseMeta = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// Step indicators
	StepStyle  = lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
	FoundStyle = lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true)
	FailStyle  = lipgloss.NewStyle().Foreground(ColorError).Bold(true)
	WarnStyle  = lipgloss.NewStyle().Foreground(ColorWarning).Bold(true)
	MutedStyle = lipgloss.NewStyle().Foreground(ColorMuted)
	DimStyle   = lipgloss.NewStyle().Foreground(ColorMuted).Faint(true)

	// Badge styles
	BadgeSuccess = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	BadgeWarning = lipgloss.NewStyle().
			Foreground(ColorWarning).
			Bold(true)

	BadgeError = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	BadgeInfo = lipgloss.NewStyle().
			Foreground(ColorInfo).
			Bold(true)

	BadgeCount = lipgloss.NewStyle().
			Foreground(ColorHighlight).
			Bold(true)

	// Value styles
	ValStyle    = lipgloss.NewStyle().Foreground(ColorWarning)
	KeyStyle    = lipgloss.NewStyle().Foreground(ColorHighlight)
	PathStyle   = lipgloss.NewStyle().Foreground(ColorCyan)
	HostStyle   = lipgloss.NewStyle().Foreground(ColorSecondary)
	DomainStyle = lipgloss.NewStyle().Foreground(ColorPurple)

	// Layout helpers
	Divider = lipgloss.NewStyle().
		Foreground(ColorSecondary).
		Render("  " + "─")

	Bullet = lipgloss.NewStyle().
		Foreground(ColorSecondary).
		Render("·")

	Arrow = lipgloss.NewStyle().
		Foreground(ColorCyan).
		Render("→")

	Check = lipgloss.NewStyle().
		Foreground(ColorSuccess).
		Bold(true).
		Render("✓")

	Cross = lipgloss.NewStyle().
		Foreground(ColorError).
		Bold(true).
		Render("✗")

	Dot = lipgloss.NewStyle().
		Foreground(ColorWarning).
		Bold(true).
		Render("●")

	EmptyDot = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Render("○")
)
