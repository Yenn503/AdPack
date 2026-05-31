package utils

import "charm.land/lipgloss/v2"

var (
	ColorPrimary       = lipgloss.Color("#00E5FF")
	ColorSecondary     = lipgloss.Color("#82B1FF")
	ColorMuted         = lipgloss.Color("#546E7A")
	ColorHighlight     = lipgloss.Color("#FFD740")
	ColorTextOnPrimary = lipgloss.Color("#0D1117")

	ColorSuccess = lipgloss.Color("#00E676")
	ColorWarning = lipgloss.Color("#FF9100")
	ColorError   = lipgloss.Color("#FF1744")
	ColorInfo    = lipgloss.Color("#448AFF")
	ColorCyan    = lipgloss.Color("#18FFFF")
	ColorPurple  = lipgloss.Color("#B388FF")
	ColorPink    = lipgloss.Color("#FF80AB")
	ColorLime    = lipgloss.Color("#C6FF00")

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

	StepStyle  = lipgloss.NewStyle().Foreground(ColorCyan).Bold(true)
	FoundStyle = lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true)
	FailStyle  = lipgloss.NewStyle().Foreground(ColorError).Bold(true)
	WarnStyle  = lipgloss.NewStyle().Foreground(ColorWarning).Bold(true)
	MutedStyle = lipgloss.NewStyle().Foreground(ColorMuted)
	DimStyle   = lipgloss.NewStyle().Foreground(ColorMuted).Faint(true)

	BadgeSuccess = lipgloss.NewStyle().Foreground(ColorSuccess).Bold(true)
	BadgeWarning = lipgloss.NewStyle().Foreground(ColorWarning).Bold(true)
	BadgeError   = lipgloss.NewStyle().Foreground(ColorError).Bold(true)
	BadgeInfo    = lipgloss.NewStyle().Foreground(ColorInfo).Bold(true)
	BadgeCount   = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true)

	ValStyle    = lipgloss.NewStyle().Foreground(ColorWarning)
	KeyStyle    = lipgloss.NewStyle().Foreground(ColorHighlight)
	PathStyle   = lipgloss.NewStyle().Foreground(ColorCyan)
	HostStyle   = lipgloss.NewStyle().Foreground(ColorSecondary)
	DomainStyle = lipgloss.NewStyle().Foreground(ColorPurple)

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

	CrackPanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorHighlight).
			Padding(0, 2).
			MarginTop(1).
			MarginBottom(1)

	CrackLabel = lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true)

	CrackCount = lipgloss.NewStyle().
			Foreground(ColorHighlight).
			Bold(true)

	CrackPending = lipgloss.NewStyle().
			Foreground(ColorMuted)

	CrackActive = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	CrackBar = lipgloss.NewStyle().
			Foreground(ColorHighlight)

	PanelBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorSecondary).
			Padding(0, 2).
			MarginTop(1).
			MarginBottom(1)

	TableHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorSecondary).
			Padding(0, 1)

	TableRow = lipgloss.NewStyle().
			Foreground(ColorHighlight)

	TableDivider = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Faint(true)

	PhaseLabel = lipgloss.NewStyle().
			Foreground(ColorPrimary).
			Bold(true)

	PhaseName = lipgloss.NewStyle().
			Foreground(ColorHighlight).
			Bold(true).
			Italic(true)
)
