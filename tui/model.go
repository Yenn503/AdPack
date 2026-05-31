package tui

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"adpack/core"
	"adpack/internal/cracker"
	"adpack/modules"
	"adpack/storage"
	"adpack/utils"
	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type view int

const (
	viewStatus view = iota
	viewGaps
	viewRecommendation
	viewCreds
	viewTransport
)

var views = []view{viewStatus, viewGaps, viewRecommendation, viewCreds, viewTransport}
var viewNames = []string{"Status", "Gaps", "Recommendations", "Credentials", "Transport"}

var stdoutMu sync.Mutex

// Internal messages for phase execution.
type phaseOutputLineMsg string
type phaseFinishedMsg struct {
	Phase   core.Phase
	Success bool
	Error   string
	Lines   []string
}

type model struct {
	db            *storage.DB
	state         *core.ADState
	crackQueue    *cracker.HashQueue
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

	// Phase execution
	phaseOutput  []string
	runningPhase core.Phase
	showOutput   bool
	phaseCh      chan tea.Msg
	phaseCancel  context.CancelFunc
}

type keyMap struct {
	Up        key.Binding
	Down      key.Binding
	Tab       key.Binding
	RunPhase1 key.Binding
	RunPhase2 key.Binding
	RunPhase3 key.Binding
	RunPhase4 key.Binding
	RunPhase5 key.Binding
	RunPhase6 key.Binding
	RunPhase7 key.Binding
	RunPhase8 key.Binding
	RunPhase9 key.Binding
	Autorun   key.Binding
	Creds     key.Binding
	Transport key.Binding
	Esc       key.Binding
	Refresh   key.Binding
	Quit      key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Autorun, k.Refresh, k.Quit}
}
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.RunPhase1, k.RunPhase2, k.RunPhase3, k.RunPhase4, k.RunPhase5},
		{k.RunPhase6, k.RunPhase7, k.RunPhase8, k.RunPhase9},
		{k.Autorun, k.Creds, k.Transport, k.Refresh, k.Quit},
	}
}

var keys = keyMap{
	Up:   key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down: key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Tab:  key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "cycle views")),

	RunPhase1: key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "run discovery")),
	RunPhase2: key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "run enumeration")),
	RunPhase3: key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "run cred acq")),
	RunPhase4: key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "run session harvest")),
	RunPhase5: key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "run graph analysis")),
	RunPhase6: key.NewBinding(key.WithKeys("6"), key.WithHelp("6", "run lateral")),
	RunPhase7: key.NewBinding(key.WithKeys("7"), key.WithHelp("7", "run validation")),
	RunPhase8: key.NewBinding(key.WithKeys("8"), key.WithHelp("8", "run privesc")),
	RunPhase9: key.NewBinding(key.WithKeys("9"), key.WithHelp("9", "run persistence")),

	Autorun: key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "autorun")),

	Creds:     key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "credentials")),
	Transport: key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "transport")),
	Esc:       key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
	Refresh:   key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
	Quit:      key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
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
	s.NormalDesc = s.NormalDesc.Foreground(utils.ColorMuted)
	s.SelectedDesc = s.SelectedDesc.Foreground(utils.ColorMuted)
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

func New(db *storage.DB, crackQueue *cracker.HashQueue) tea.Model {
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
		db:         db,
		state:      state,
		crackQueue: crackQueue,
		spinner:    s,
		viewport:   vp,
		gapsList:   newGapsList(),
		recList:    newRecList(),
		prog:       newProgress(),
		help:       help.New(),
		keys:       keys,
		err:        nil,
		phaseCh:    make(chan tea.Msg, 1024),
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

	// Process channel-based phase messages.
	select {
	case internalMsg, ok := <-m.phaseCh:
		if !ok {
			m.phaseCh = nil
		} else {
			switch im := internalMsg.(type) {
			case phaseOutputLineMsg:
				m.phaseOutput = append(m.phaseOutput, string(im))
				m.viewport.SetContent(strings.Join(m.phaseOutput, "\n"))
				m.viewport.GotoBottom()
				return m, readFromCh(m.phaseCh)
			case phaseFinishedMsg:
				m.runningPhase = ""
				if im.Success {
					m.phaseOutput = append(m.phaseOutput, "", utils.SuccessStyle.Render("✓ Phase completed successfully"))
				} else {
					errMsg := im.Error
					if errMsg == "" {
						errMsg = "phase failed"
					}
					m.phaseOutput = append(m.phaseOutput, "", utils.ErrorStyle.Render("✗ "+errMsg))
				}
				m.viewport.SetContent(strings.Join(m.phaseOutput, "\n"))
				m.viewport.GotoBottom()
				// Reload state from DB.
				s, err := m.db.LoadState()
				if err == nil {
					m.state = s
				}
				m.rebuildLists()
				return m, nil
			}
		}
	default:
	}

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

		case key.Matches(msg, m.keys.Esc):
			if m.phaseCancel != nil {
				m.phaseCancel()
				m.phaseCancel = nil
			}
			m.showOutput = false
			m.runningPhase = ""
			m.phaseOutput = nil
			m.viewport.SetContent("")

		case m.runningPhase != "":
			// Ignore other keys while a phase is running.

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

		case key.Matches(msg, m.keys.Creds):
			m.currentView = viewCreds
			m.rebuildLists()

		case key.Matches(msg, m.keys.Transport):
			m.currentView = viewTransport
			m.rebuildLists()

		case key.Matches(msg, m.keys.Refresh):
			s, err := m.db.LoadState()
			if err == nil {
				m.state = s
			}
			m.rebuildLists()

		case key.Matches(msg, m.keys.RunPhase1):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhaseDiscovery
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhaseDiscovery, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase2):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhaseEnumeration
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhaseEnumeration, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase3):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhaseCredentialAcq
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhaseCredentialAcq, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase4):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhaseSessionHarvest
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhaseSessionHarvest, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase5):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhaseGraphAnalysis
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhaseGraphAnalysis, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase6):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhaseLateral
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhaseLateral, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase7):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhaseValidation
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhaseValidation, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase8):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhasePrivEsc
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhasePrivEsc, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.RunPhase9):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.PhasePersistence
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runPhaseAndStream(ctx, core.PhasePersistence, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)

		case key.Matches(msg, m.keys.Autorun):
			if m.phaseCancel != nil {
				m.phaseCancel()
			}
			m.showOutput = true
			m.runningPhase = core.Phase("autorun")
			m.phaseOutput = nil
			m.phaseCh = make(chan tea.Msg, 1024)
			ctx, cancel := context.WithCancel(context.Background())
			m.phaseCancel = cancel
			go runAutorunAndStream(ctx, m.state, m.db, m.phaseCh)
			return m, tea.Batch(readFromCh(m.phaseCh), m.spinner.Tick)
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

// readFromCh returns a Cmd that reads one message from the channel.
func readFromCh(ch chan tea.Msg) tea.Cmd {
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

// runPhaseAndStream runs a phase in a goroutine, capturing stdout and sending
// line-by-line output to the channel. Sends a phaseFinishedMsg when done.
func runPhaseAndStream(ctx context.Context, phase core.Phase, state *core.ADState, db *storage.DB, ch chan<- tea.Msg) {
	defer close(ch)

	select {
	case <-ctx.Done():
		return
	default:
	}

	r, w, err := os.Pipe()
	if err != nil {
		ch <- phaseFinishedMsg{Phase: phase, Success: false, Error: err.Error()}
		return
	}

	stdoutMu.Lock()
	orig := os.Stdout
	os.Stdout = w
	stdoutMu.Unlock()

	// Read captured stdout line by line and stream to channel.
	lineCh := make(chan string, 256)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
	}()

	// Forward lines from lineCh to ch (non-blocking).
	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		for line := range lineCh {
			select {
			case ch <- phaseOutputLineMsg(line):
			case <-ctx.Done():
				return
			}
		}
	}()

	success, errStr := executePhase(phase, state, db)

	stdoutMu.Lock()
	w.Close()
	os.Stdout = orig
	stdoutMu.Unlock()

	<-readDone
	close(lineCh)
	<-forwardDone

	ch <- phaseFinishedMsg{
		Phase:   phase,
		Success: success,
		Error:   errStr,
	}
}

// executePhase runs the given phase, persisting results to DB.
func executePhase(phase core.Phase, state *core.ADState, db *storage.DB) (bool, string) {
	state.Phases[phase] = core.PhaseInProgress
	if err := db.SavePhases(state); err != nil {
		return false, fmt.Sprintf("save phase status: %v", err)
	}

	var success bool

	switch phase {
	case core.PhaseDiscovery:
		result := modules.RunDiscovery(state, "", nil)
		success = result.Success
		if result.Success {
			for _, h := range result.Hosts {
				if err := db.SaveHost(h); err != nil {
					return false, fmt.Sprintf("save host: %v", err)
				}
			}
			for _, ev := range result.Evidence {
				if err := db.SaveEvidence(ev); err != nil {
					return false, fmt.Sprintf("save evidence: %v", err)
				}
			}
		}

	case core.PhaseEnumeration:
		result := modules.RunEnumeration(state, "")
		success = result.Success
		if result.Success {
			for _, u := range result.Users {
				if err := db.SaveUser(u); err != nil {
					return false, fmt.Sprintf("save user: %v", err)
				}
			}
			for _, c := range result.Creds {
				if err := db.SaveCred(c); err != nil {
					return false, fmt.Sprintf("save cred: %v", err)
				}
			}
			for _, ev := range result.Evidence {
				if err := db.SaveEvidence(ev); err != nil {
					return false, fmt.Sprintf("save evidence: %v", err)
				}
			}
		}

	case core.PhaseCredentialAcq:
		result := modules.RunCredentialAcq(state, "standard", "")
		success = result.Success
		for _, ev := range result.Evidence {
			if err := db.SaveEvidence(ev); err != nil {
				return false, fmt.Sprintf("save evidence: %v", err)
			}
		}
		if result.Success {
			for _, c := range result.Creds {
				if err := db.SaveCred(c); err != nil {
					return false, fmt.Sprintf("save cred: %v", err)
				}
			}
		}

	case core.PhaseValidation:
		result := modules.RunValidation(state, "")
		success = result.Success
		for _, ev := range result.Evidence {
			if err := db.SaveEvidence(ev); err != nil {
				return false, fmt.Sprintf("save evidence: %v", err)
			}
		}
		if err := db.SaveState(state); err != nil {
			return false, fmt.Sprintf("save state: %v", err)
		}

	case core.PhaseSessionHarvest:
		provider, pErr := modules.ProviderFromState(state, "", core.NoopSink{})
		if pErr != nil {
			fmt.Printf("[!] %v\n", pErr)
			success = false
			break
		}
		result := modules.RunSessionHarvest(context.Background(), provider, state)
		success = result.Success
		if result.Success {
			for _, ev := range result.Evidence {
				if err := db.SaveEvidence(ev); err != nil {
					return false, fmt.Sprintf("save evidence: %v", err)
				}
			}
			if err := db.SaveSessions(result.Sessions); err != nil {
				return false, fmt.Sprintf("save sessions: %v", err)
			}
			state.Sessions = result.Sessions
		}

	case core.PhaseGraphAnalysis:
		provider, pErr := modules.ProviderFromState(state, "", core.NoopSink{})
		if pErr != nil {
			fmt.Printf("[!] %v\n", pErr)
			success = false
			break
		}
		result := modules.RunGraphAnalysis(context.Background(), provider)
		success = result.Success
		if result.Success {
			for _, c := range result.Computers {
				if err := db.SaveComputer(c); err != nil {
					return false, fmt.Sprintf("save computer: %v", err)
				}
			}
			for _, g := range result.GPOs {
				if err := db.SaveGPO(g); err != nil {
					return false, fmt.Sprintf("save GPO: %v", err)
				}
			}
			for _, t := range result.ADCS {
				if err := db.SaveADCSTemplate(t); err != nil {
					return false, fmt.Sprintf("save ADCS: %v", err)
				}
			}
			for _, ev := range result.Evidence {
				if err := db.SaveEvidence(ev); err != nil {
					return false, fmt.Sprintf("save evidence: %v", err)
				}
			}
			for _, u := range result.Users {
				if err := db.SaveUser(u); err != nil {
					return false, fmt.Sprintf("save user: %v", err)
				}
			}
		}

	case core.PhaseLateral:
		result := modules.RunLateral(state, "")
		success = result.Success
		if result.Success {
			for _, h := range result.Hosts {
				if err := db.SaveHost(h); err != nil {
					return false, fmt.Sprintf("save host: %v", err)
				}
			}
			for _, ev := range result.Evidence {
				if err := db.SaveEvidence(ev); err != nil {
					return false, fmt.Sprintf("save evidence: %v", err)
				}
			}
		}

	case core.PhasePrivEsc:
		result := modules.RunPrivesc(state, "", "standard", false)
		success = result.Success
		if result.Success {
			for _, ev := range result.Evidence {
				if err := db.SaveEvidence(ev); err != nil {
					return false, fmt.Sprintf("save evidence: %v", err)
				}
			}
		}

	case core.PhasePersistence:
		result := modules.RunPersistence(state, "")
		success = result.Success
		if result.Success {
			for _, ev := range result.Evidence {
				if err := db.SaveEvidence(ev); err != nil {
					return false, fmt.Sprintf("save evidence: %v", err)
				}
			}
		}

	default:
		return false, fmt.Sprintf("unknown phase: %s", phase)
	}

	// Update phase status.
	if success {
		state.Phases[phase] = core.PhaseComplete
	} else {
		state.Phases[phase] = core.PhaseFailed
	}
	if err := db.SavePhases(state); err != nil {
		return false, fmt.Sprintf("save final phases: %v", err)
	}

	return success, ""
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

	if m.err != nil {
		return tea.NewView(utils.ErrorStyle.Render(fmt.Sprintf("Error: %v", m.err)))
	}

	if m.showOutput {
		return m.outputView()
	}

	var content string
	switch m.currentView {
	case viewStatus:
		content = m.statusView()
	case viewGaps:
		content = m.gapsView()
	case viewRecommendation:
		content = m.recView()
	case viewCreds:
		content = m.credsView()
	case viewTransport:
		content = m.transportView()
	}

	m.viewport.SetContent(content)

	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(utils.ColorSecondary).
		MarginTop(1).
		Render(m.spinner.View() + " ADPack  |  " + time.Now().Format("2006-01-02 15:04:05"))

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

// outputView renders the phase output screen.
func (m model) outputView() tea.View {
	var b strings.Builder

	phaseName := string(m.runningPhase)
	if phaseName == "" {
		phaseName = "complete"
	}

	statusLine := ""
	if m.runningPhase != "" {
		statusLine = m.spinner.View() + " Running phase: " + phaseName
	} else {
		statusLine = "Phase: " + phaseName + " (finished)"
	}

	b.WriteString(utils.PhaseTitle.Render(statusLine))
	b.WriteString("\n\n")

	// Show output lines through viewport.
	m.viewport.SetContent(strings.Join(m.phaseOutput, "\n"))
	b.WriteString(utils.OutputBox.Render(m.viewport.View()))
	b.WriteString("\n\n")
	b.WriteString(utils.MutedStyle.Render("Press esc to return to dashboard"))

	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}

// credsView renders the credentials table.
func (m model) credsView() string {
	cols := []table.Column{
		{Title: "Domain", Width: 20},
		{Title: "Username", Width: 20},
		{Title: "Type", Width: 12},
		{Title: "Secret", Width: 24},
		{Title: "Validated", Width: 10},
	}
	rows := make([]table.Row, 0, len(m.state.Creds))
	for _, c := range m.state.Creds {
		secret := c.Secret
		if secret == "" && c.Hash != "" {
			secret = c.Hash[:min(len(c.Hash), 16)]
		}
		validStr := "no"
		if c.Validated {
			validStr = utils.SuccessStyle.Render("yes")
		}
		rows = append(rows, table.Row{
			c.Domain,
			c.Username,
			string(c.Type),
			secret,
			validStr,
		})
	}

	t := table.New(table.WithColumns(cols), table.WithRows(rows), table.WithFocused(false))
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(utils.ColorSecondary).Bold(true)
	s.Selected = s.Selected.Foreground(utils.ColorSuccess).Bold(true)
	t.SetStyles(s)

	header := utils.TitleStyle.Render("Credentials (" + fmt.Sprintf("%d", len(m.state.Creds)) + ")")
	return header + "\n\n" + t.View()
}

// transportView renders the transport configuration.
func (m model) transportView() string {
	var b strings.Builder
	b.WriteString(utils.TitleStyle.Render("Transport Configuration"))
	b.WriteString("\n\n")

	b.WriteString(utils.InfoStyle.Render("Transport type: local"))
	b.WriteString("\n\n")

	hostCount := len(m.state.Hosts)
	b.WriteString(fmt.Sprintf("Available hosts: %d\n", hostCount))
	if hostCount > 0 {
		for _, h := range m.state.Hosts {
			dc := ""
			if h.IsDC {
				dc = " [DC]"
			}
			b.WriteString(fmt.Sprintf("  %s%s  %s\n", h.IP, dc, h.Hostname))
		}
	}

	b.WriteString(fmt.Sprintf("\nAD Sessions: %d\n", len(m.state.Sessions)))
	if len(m.state.Sessions) > 0 {
		for _, s := range m.state.Sessions {
			b.WriteString(fmt.Sprintf("  User=%s Host=%s\n", s.Username, s.Host))
		}
	}

	return b.String()
}

func (m *model) rebuildTables() {
	cols := []table.Column{
		{Title: "Phase", Width: 16},
		{Title: "Status", Width: 12},
		{Title: "Reason", Width: 18},
	}
	rows := []table.Row{}
	for _, p := range core.AllPhases {
		st := m.state.Phases[p]
		label := func(st core.PhaseStatus) string {
			switch st {
			case core.PhaseComplete:
				return utils.SuccessStyle.Render("done")
			case core.PhaseInProgress:
				return utils.InfoStyle.Render("in-progress")
			case core.PhaseFailed:
				return utils.ErrorStyle.Render("failed")
			case core.PhaseSkipped:
				return utils.WarningStyle.Render("skipped")
			default:
				return utils.MutedStyle.Render("pending")
			}
		}(st)
		reason := ""
		if (st == core.PhaseSkipped || st == core.PhaseFailed) && m.state.SkipReasons != nil {
			reason = string(m.state.SkipReasons[p])
		}
		rows = append(rows, table.Row{
			string(p), label, reason,
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

	if m.runningPhase != "" {
		b.WriteString(utils.WarningStyle.Render(fmt.Sprintf("⚠ Phase %s is running — press esc to view output", m.runningPhase)))
		b.WriteString("\n\n")
	}

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

	stats := fmt.Sprintf("Hosts: %d | Computers: %d | Users: %d | Creds: %d (%d val) | Sessions: %d | BH: %v\n\n",
		len(m.state.Hosts), len(m.state.Computers), len(m.state.Users),
		len(m.state.Creds), countVal(m.state.Creds),
		len(m.state.Sessions), m.state.BH.Collected)

	b.WriteString(utils.InfoStyle.Render(stats))
	b.WriteString(fmt.Sprintf("  Campaign: %d/%d phases  %s\n\n", completed, len(core.AllPhases), m.prog.View()))
	b.WriteString(m.crackStatsView())
	b.WriteString("\n")
	b.WriteString(m.phaseRationaleView())
	b.WriteString("\n")
	b.WriteString(m.statusTable.View())

	if len(m.state.Edges) > 0 {
		b.WriteString("\n\n")
		b.WriteString(utils.TitleStyle.Render("Top Privilege Edges"))
		b.WriteString("\n")
		counts := make(map[string]int)
		for _, e := range m.state.Edges {
			counts[e.AccessRight]++
		}
		type ec struct {
			name  string
			count int
		}
		var sorted []ec
		for k, v := range counts {
			sorted = append(sorted, ec{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		top := sorted
		if len(top) > 5 {
			top = top[:5]
		}
		for _, e := range top {
			b.WriteString(fmt.Sprintf("  %s  %d\n", e.name, e.count))
		}
	}

	return b.String()
}

func (m model) crackStatsView() string {
	if m.crackQueue == nil {
		return ""
	}

	stats := m.crackQueue.Stats()

	running := ""
	if stats.IsRunning {
		running = utils.CrackActive.Render(" ● ACTIVE")
	} else if stats.TotalEnqueued > 0 {
		running = utils.MutedStyle.Render(" ○ IDLE")
	} else {
		return ""
	}

	var b strings.Builder

	detail := fmt.Sprintf("Enqueued: %d  |  Cracked: %d  |  Pending: %d%s",
		stats.TotalEnqueued, stats.TotalCracked, stats.TotalPending, running)

	if len(stats.ByType) > 0 {
		var parts []string
		for _, ht := range []cracker.HashType{cracker.HashKRB5TGS, cracker.HashKRB5ASREP, cracker.HashNTLM} {
			if ts, ok := stats.ByType[ht]; ok {
				parts = append(parts, fmt.Sprintf("%s: %d pend", ts.HashType, ts.Pending))
			}
		}
		if len(parts) > 0 {
			detail += "  |  " + strings.Join(parts, "  ")
		}
	}

	b.WriteString(utils.CrackPanel.Render(utils.CrackLabel.Render("▌ Crack Queue") + "\n" + detail))
	return b.String()
}

func (m model) phaseRationaleView() string {
	engine := core.NewEngine(m.state)
	rec := engine.Evaluate()

	if rec.Phase == "" {
		return ""
	}

	var b strings.Builder
	status := m.state.Phases[rec.Phase]
	statusStr := "untouched"
	if status == core.PhaseComplete {
		statusStr = "complete"
	} else if status == core.PhaseInProgress {
		statusStr = "in-progress"
	} else if status == core.PhaseFailed {
		statusStr = "failed"
	} else if status == core.PhaseSkipped {
		statusStr = "skipped"
	}

	b.WriteString(utils.PhaseBox.Render(
		fmt.Sprintf("%s %s\n%s",
			utils.PhaseLabel.Render("▌ Next Phase"),
			utils.PhaseName.Render(string(rec.Phase)+" ("+statusStr+")"),
			utils.MutedStyle.Render(rec.Rationale),
		),
	))
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// runAutorunAndStream runs all pending phases sequentially, streaming output.
func runAutorunAndStream(ctx context.Context, state *core.ADState, db *storage.DB, ch chan<- tea.Msg) {
	defer close(ch)

	select {
	case <-ctx.Done():
		return
	default:
	}

	r, w, err := os.Pipe()
	if err != nil {
		ch <- phaseFinishedMsg{Phase: "autorun", Success: false, Error: err.Error()}
		return
	}

	stdoutMu.Lock()
	orig := os.Stdout
	os.Stdout = w
	stdoutMu.Unlock()

	lineCh := make(chan string, 256)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			lineCh <- scanner.Text()
		}
	}()

	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		for line := range lineCh {
			select {
			case ch <- phaseOutputLineMsg(line):
			case <-ctx.Done():
				return
			}
		}
	}()

	allSuccess := true
	for _, p := range core.AllPhases {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if state.Phases[p] == core.PhaseComplete {
			continue
		}
		fmt.Printf("\n  → Running %s...\n", p)
		success, errStr := executePhase(p, state, db)
		if !success {
			fmt.Printf("  ✗ %s failed: %s\n", p, errStr)
			allSuccess = false
		} else {
			fmt.Printf("  ✓ %s completed\n", p)
		}
	}

	stdoutMu.Lock()
	w.Close()
	os.Stdout = orig
	stdoutMu.Unlock()
	<-readDone
	close(lineCh)
	<-forwardDone

	if allSuccess {
		ch <- phaseFinishedMsg{Phase: "autorun", Success: true}
	} else {
		ch <- phaseFinishedMsg{Phase: "autorun", Success: false, Error: "some phases failed"}
	}
}
