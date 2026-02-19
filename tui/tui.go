package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ekzyis/lnpilot/tui/components"
)

type initialModel struct {
	width, height int
	sidePane      *components.SidePane
	mainPane      *components.MainPane
}

var _ tea.Model = (*initialModel)(nil)

func NewProgram() *tea.Program {
	return tea.NewProgram(
		newInitialModel(),
		tea.WithAltScreen(),
	)
}

func newInitialModel() tea.Model {
	return &initialModel{
		sidePane: components.NewSidePane(),
		mainPane: components.NewMainPane(),
	}
}

func (m *initialModel) Init() tea.Cmd {
	return nil
}

func (m *initialModel) View() string {
	sidePaneWidth := 40
	sidePane := lipgloss.NewStyle().
		Width(sidePaneWidth).
		Height(m.height).
		AlignVertical(lipgloss.Top).
		Render(m.sidePane.Render())
	mainPane := lipgloss.NewStyle().
		Width(m.width - sidePaneWidth).
		Height(m.height).
		PaddingRight(sidePaneWidth).
		AlignHorizontal(lipgloss.Center).
		AlignVertical(lipgloss.Center).
		Render(m.mainPane.Render())
	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		sidePane,
		mainPane,
	)
}

func (m *initialModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.KeyMsg:
		if cmd = handleGlobalKey(msg); cmd != nil {
			return m, cmd
		}
		_ = m.sidePane.OnMessage(msg)
	}
	m.mainPane.SetSelected(m.sidePane.Selected())
	return m, cmd
}

func handleGlobalKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		return tea.Quit
	}
	return nil
}
