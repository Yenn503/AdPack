package utils

import "github.com/charmbracelet/lipgloss"

var (
	// Professional color palette for security tooling
	ColorPrimary   = lipgloss.Color("#0066CC") // Professional Blue
	ColorSecondary = lipgloss.Color("#5C6BC0") // Indigo
	ColorSuccess   = lipgloss.Color("#2E7D32") // Forest Green
	ColorWarning   = lipgloss.Color("#F57C00") // Amber
	ColorError     = lipgloss.Color("#C62828") // Deep Red
	ColorMuted     = lipgloss.Color("#757575") // Gray
	ColorInfo      = lipgloss.Color("#0288D1") // Light Blue
	ColorHighlight = lipgloss.Color("#1976D2") // Bright Blue

	// Common Styles
	BaseStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0"))
	
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
