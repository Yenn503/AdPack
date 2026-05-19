package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
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
	gapsList      list.Model
	recList       list.Model
	prog          progress.Model
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

type gapItem struct {
	gap core.Gap
}

func (i gapItem) Title() string {
	return fmt.Sprintf("[%s] %s", strings.ToUpper(i.gap.Severity), i.gap.Phase)
}
func (i gapItem) Description() string { return i.gap.Message }
func (i gapItem) FilterValue() string {
	return i.gap.Message + " " + string(i.gap.Phase)
}

type strategyItem struct {
	name string
}

func (i strategyItem) Title() string       { return strings.ReplaceAll(i.name, "_", " ") }
func (i strategyItem) Description() string { return "" }
func (i strategyItem) FilterValue() string { return i.name }

func newGapsList() list.Model {
	d := list.NewDefaultDelegate()
	d.ShowDescription = true
	s := list.NewDefaultItemStyles(true)
	s.SelectedTitle = s.SelectedTitle.
		Foreground(utils.ColorPrimary).
		BorderLeftForeground(utils.ColorPrimary)
	s.SelectedDesc = s.SelectedDesc.Foreground(utils.ColorMuted)
	s.NormalTitle = s.NormalTitle.Foreground(utils.ColorSecondary)
	d.Styles = s
	l := list.New([]list.Item{}, d, 0, 0)
	l.Title = "Detected Workflow Gaps"
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)
	l.SetSpinner(spinner.Dot)
	return l
}

func newRecList() list.Model {
	d := list.NewDefaultDelegate()
	d.ShowDescription = false
	s := list.NewDefaultItemStyles(true)
	s.SelectedTitle = s.SelectedTitle.
		Foreground(utils.ColorSecondary).
		BorderLeftForeground(utils.ColorSecondary)
	s.NormalTitle = s.NormalTitle.Foreground(utils.ColorSecondary)
	d.Styles = s
	l := list.New([]list.Item{}, d, 0, 0)
	l.Title = "Recommended Strategies"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	return l
}

func newProgress() progress.Model {
	return progress.New(
		progress.WithWidth(40),
		progress.WithScaled(true),
		progress.WithColors(
			utils.ColorError,
			utils.ColorWarning,
			utils.ColorSuccess,
		),
	)
}

func New(db *storage.DB) tea.Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(utils.ColorPrimary)

	state, err := db.LoadState()
	if err != nil {
		state = core.NewADState()
	}

	vp := viewport.New()
	vp.Style = lipgloss.NewStyle()

	return model{
		db:        db,
		state:     state,
		spinner:   s,
		viewport:  vp,
		gapsList:  newGapsList(),
		recList:   newRecList(),
		prog:      newProgress(),
		help:      help.New(),
		keys:      keys,
		err:       nil,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tea.RequestWindowSize)
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

		headerHeight := 8
		footerHeight := 2
		vpHeight := msg.Height - headerHeight - footerHeight
		if vpHeight < 0 {
			vpHeight = 0
		}

		m.viewport.SetWidth(msg.Width - 4)
		m.viewport.SetHeight(vpHeight)

		m.gapsList.SetWidth(msg.Width - 6)
		m.gapsList.SetHeight(vpHeight)

		m.recList.SetWidth(msg.Width - 6)
		m.recList.SetHeight(vpHeight)

		m.rebuildTables()
		return m, nil

	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.Status):
			m.currentView = viewStatus
			m.rebuildLists()
		case key.Matches(msg, m.keys.Gaps):
			m.currentView = viewGaps
			m.rebuildLists()
		case key.Matches(msg, m.keys.Next):
			m.currentView = viewRecommendation
			m.rebuildLists()
		case key.Matches(msg, m.keys.Refresh):
			s, err := m.db.LoadState()
			if err == nil {
				m.state = s
			}
			m.rebuildLists()
		case key.Matches(msg, m.keys.Tab):
			idx := 0
			for i, v := range views {
				if v == m.currentView {
					idx = i
					break
				}
			}
			m.currentView = views[(idx+1)%len(views)]
			m.rebuildLists()
		}

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	switch m.currentView {
	case viewGaps:
		m.gapsList, cmd = m.gapsList.Update(msg)
		cmds = append(cmds, cmd)
	case viewRecommendation:
		m.recList, cmd = m.recList.Update(msg)
		cmds = append(cmds, cmd)
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m model) renderTabs() string {
	var tabs []string

	activeTabStyle := lipgloss.NewStyle().
		Background(utils.ColorPrimary).
		Foreground(utils.ColorTextOnPrimary).
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

func (m model) View() tea.View {
	if !m.ready {
		v := tea.NewView("\n  Loading...")
		v.AltScreen = true
		return v
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

	v := tea.NewView(lipgloss.JoinVertical(lipgloss.Left,
		header,
		"",
		m.renderTabs(),
		utils.ContainerStyle.Render(m.viewport.View()),
		"",
		helpView,
	))
	v.AltScreen = true
	return v
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
	s.Selected = s.Selected.Foreground(utils.ColorSuccess).Bold(true)
	t.SetStyles(s)
	m.statusTable = t
}

func (m *model) rebuildLists() {
	m.rebuildTables()

	gaps := m.state.DetectGaps()
	items := make([]list.Item, len(gaps))
	for i, g := range gaps {
		items[i] = gapItem{gap: g}
	}
	m.gapsList.SetItems(items)

	engine := core.NewEngine(m.state)
	rec := engine.Evaluate()
	stratItems := make([]list.Item, len(rec.Strategies))
	for i, s := range rec.Strategies {
		stratItems[i] = strategyItem{name: s}
	}
	m.recList.SetItems(stratItems)
}

func (m model) statusView() string {
	var b strings.Builder

	completed := 0
	for _, p := range core.AllPhases {
		if m.state.Phases[p] == core.PhaseComplete {
			completed++
		}
	}
	pct := float64(completed) / float64(len(core.AllPhases))
	m.prog.SetPercent(pct)
	m.prog.SetWidth(m.width - 10)
	if m.width-10 < 10 {
		m.prog.SetWidth(10)
	}

	stats := fmt.Sprintf("Hosts: %d | Users: %d | Creds: %d (%d val) | Sessions: %d | BH: %v\n\n",
		len(m.state.Hosts), len(m.state.Users),
		len(m.state.Creds), countVal(m.state.Creds),
		len(m.state.Sessions), m.state.BH.Collected)

	b.WriteString(utils.InfoStyle.Render(stats))
	b.WriteString(fmt.Sprintf("  Campaign: %d/9 phases  %s\n\n", completed, m.prog.View()))
	b.WriteString(m.statusTable.View())
	return b.String()
}

func (m model) gapsView() string {
	gaps := m.state.DetectGaps()
	if len(gaps) == 0 {
		return utils.SuccessStyle.Render("No gaps detected. Excellent execution.")
	}
	return m.gapsList.View()
}

func (m model) recView() string {
	engine := core.NewEngine(m.state)
	rec := engine.Evaluate()

	header := utils.TitleStyle.Render("Recommendation Engine") + "\n\n" +
		utils.InfoStyle.Render("Next Phase: ") + string(rec.Phase) + "\n\n" +
		rec.Rationale

	return header + "\n\n" + utils.TitleStyle.Render("Strategies") + "\n\n" + m.recList.View()
}

func countVal(cc []core.Credential) int {
	n := 0
	for _, c := range cc {
		if c.Validated {
			n++
		}
	}
	return n
}
