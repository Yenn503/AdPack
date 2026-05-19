package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"adpack/core"
	"adpack/storage"
	"adpack/utils"
)

type view int
const (
	viewStatus view = iota
	viewGaps
	viewRecommendation
)

var views = []view{viewStatus, viewGaps, viewRecommendation}
var viewNames = []string{"Status", "Gaps", "Recommendations"}

type model struct {
	db            *storage.DB
	state         *core.ADState
	currentView   view
	ready         bool
	spinner       spinner.Model
	viewport      viewport.Model
	help          help.Model
	keys          keyMap
	statusTable   table.Model
	width, height int
	err           error
}

type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	Tab      key.Binding
	Status   key.Binding
	Gaps     key.Binding
	Next     key.Binding
	Quit     key.Binding
	Refresh  key.Binding
	RunPhase key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Refresh, k.Quit}
}
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{{k.Status, k.Gaps, k.Next, k.RunPhase, k.Refresh, k.Quit}}
}

var keys = keyMap{
	Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Tab:      key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next view")),
	Status:   key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "status view")),
	Gaps:     key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "gaps view")),
	Next:     key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "recommendation")),
	Refresh:  key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
	RunPhase: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "run phase")),
	Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

func New(db *storage.DB) tea.Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(utils.ColorPrimary)

	state, err := db.LoadState()
	if err != nil {
		state = core.NewADState()
	}
	
	vp := viewport.New(0, 0)
	vp.Style = lipgloss.NewStyle()

	return model{
		db:       db,
		state:    state,
		spinner:  s,
		viewport: vp,
		help:     help.New(),
		keys:     keys,
		err:      nil,
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		
		// Adjust viewport dynamically
		headerHeight := 8 // Spinner + Tabs + Margins
		footerHeight := 2 // Help text
		vpHeight := msg.Height - headerHeight - footerHeight
		if vpHeight < 0 {
			vpHeight = 0
		}
		
		m.viewport.Width = msg.Width - 4
		m.viewport.Height = vpHeight
		
		m.rebuildTables()
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Status):
			m.currentView = viewStatus
			m.rebuildTables()
		case key.Matches(msg, m.keys.Gaps):
			m.currentView = viewGaps
			m.rebuildTables()
		case key.Matches(msg, m.keys.Next):
			m.currentView = viewRecommendation
			m.rebuildTables()
		case key.Matches(msg, m.keys.Refresh):
			s, err := m.db.LoadState()
			if err == nil {
				m.state = s
			}
			m.rebuildTables()
		case key.Matches(msg, m.keys.RunPhase):
			if m.state != nil {
				// We don't execute full blocking tasks here without a command handler, 
				// but we can log intent or use a message
			}
		case key.Matches(msg, m.keys.Tab):
			idx := 0
			for i, v := range views {
				if v == m.currentView {
					idx = i
					break
				}
			}
			m.currentView = views[(idx+1)%len(views)]
			m.rebuildTables()
		}

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	// Update viewport with keypresses if needed
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m model) renderTabs() string {
	var tabs []string
	
	activeTabStyle := lipgloss.NewStyle().
		Background(utils.ColorPrimary).
		Foreground(lipgloss.Color("#000000")).
		Padding(0, 2).
		Bold(true)
		
	inactiveTabStyle := lipgloss.NewStyle().
		Foreground(utils.ColorMuted).
		Padding(0, 2)

	for i, name := range viewNames {
		if int(m.currentView) == i {
			tabs = append(tabs, activeTabStyle.Render(name))
		} else {
			tabs = append(tabs, inactiveTabStyle.Render(name))
		}
	}
	
	row := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
	return lipgloss.NewStyle().MarginBottom(1).Render(row)
}

func (m model) View() string {
	if !m.ready {
		return "\n  Loading..."
	}

	var content string
	switch m.currentView {
	case viewStatus:
		content = m.statusView()
	case viewGaps:
		content = m.gapsView()
	case viewRecommendation:
		content = m.recView()
	}

	m.viewport.SetContent(content)

	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(utils.ColorSecondary).
		MarginTop(1).
		Render(m.spinner.View() + " ADPack Orchestration Console")
		
	helpView := m.help.View(m.keys)

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		m.renderTabs(),
		utils.ContainerStyle.Render(m.viewport.View()),
		"",
		helpView,
	)
}

func (m *model) rebuildTables() {
	cols := []table.Column{
		{Title: "Phase", Width: 16},
		{Title: "Status", Width: 12},
	}
	rows := []table.Row{}
	for _, p := range core.AllPhases {
		st := m.state.Phases[p]
		label := map[core.PhaseStatus]string{
			core.PhaseUntouched:  "pending",
			core.PhaseInProgress: "in-progress",
			core.PhaseComplete:   "done",
			core.PhaseSkipped:    "skipped",
		}[st]
		rows = append(rows, table.Row{
			string(p), label,
		})
	}
	t := table.New(table.WithColumns(cols), table.WithRows(rows), table.WithFocused(false))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(utils.ColorSecondary).Bold(true)
	
	// Better selected row color
	s.Selected = s.Selected.Foreground(utils.ColorSuccess).Bold(true)
	
	t.SetStyles(s)
	m.statusTable = t
}

func (m model) statusView() string {
	var b strings.Builder
	
	stats := fmt.Sprintf("Hosts: %d | Users: %d | Creds: %d (%d val) | Sessions: %d | BH: %v\n\n",
		len(m.state.Hosts), len(m.state.Users),
		len(m.state.Creds), countVal(m.state.Creds),
		len(m.state.Sessions), m.state.BH.Collected)
		
	b.WriteString(utils.InfoStyle.Render(stats))
	b.WriteString(m.statusTable.View())
	return b.String()
}

func (m model) gapsView() string {
	gaps := m.state.DetectGaps()
	if len(gaps) == 0 {
		return utils.SuccessStyle.Render("No gaps detected. Excellent execution.")
	}
	var b strings.Builder
	b.WriteString(utils.TitleStyle.Render("Detected Workflow Gaps") + "\n\n")
	for _, g := range gaps {
		sevStyle := utils.ErrorStyle
		if g.Severity == "medium" {
			sevStyle = utils.WarningStyle
		}
		b.WriteString(fmt.Sprintf("  %s [%s] %s\n", sevStyle.Render(strings.ToUpper(g.Severity)), g.Phase, g.Message))
	}
	return b.String()
}

func (m model) recView() string {
	engine := core.NewEngine(m.state)
	rec := engine.Evaluate()
	
	return fmt.Sprintf("%s\n\n%s: %s\n\n%s\n\n%s:\n  - %s",
		utils.TitleStyle.Render("Recommendation Engine"),
		utils.InfoStyle.Render("Phase"), 
		rec.Phase, 
		rec.Rationale,
		utils.InfoStyle.Render("Strategies"),
		strings.Join(rec.Strategies, "\n  - "))
}

func countVal(cc []core.Credential) int {
	n := 0
	for _, c := range cc {
		if c.Validated { n++ }
	}
	return n
}
