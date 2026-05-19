package utils

import "charm.land/lipgloss/v2"

var (
	// Monochrome UI chrome
	ColorPrimary      = lipgloss.Color("#FFFFFF") // Pure white
	ColorSecondary    = lipgloss.Color("#A0A0A0") // Light gray
	ColorMuted        = lipgloss.Color("#666666") // Medium gray
	ColorHighlight    = lipgloss.Color("#E0E0E0") // Near-white
	ColorTextOnPrimary = lipgloss.Color("#1A1A1A") // Dark text on white bg

	// Semantic event colors (unchanged)
	ColorSuccess = lipgloss.Color("#2E7D32") // Forest Green
	ColorWarning = lipgloss.Color("#F57C00") // Amber
	ColorError   = lipgloss.Color("#C62828") // Deep Red
	ColorInfo    = lipgloss.Color("#0288D1") // Light Blue

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
)
