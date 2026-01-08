package model

import (
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type toolsModel struct {
	screen
	tools    *tools
	selected int
}

type tools struct {
	listModel list.Model
	style     lipgloss.Style
}

type tool struct {
	title, desc string
}

var _ tea.Model = (*toolsModel)(nil)

func (i tool) Title() string       { return i.title }
func (i tool) Description() string { return i.desc }
func (i tool) FilterValue() string { return i.title }

func newToolsModel(s screen) (tea.Model, tea.Cmd) {
	m := &toolsModel{
		screen:   s,
		selected: 0,
		tools:    newTools(s),
	}
	return m, m.Init()
}

func newTools(s screen) *tools {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		BorderForeground(lightningColor).
		Foreground(lightningColor)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		BorderForeground(lightningColor).
		Foreground(lightningColor)

	listModel := list.New(
		[]list.Item{
			tool{
				title: "bolt11",
				desc:  "everything about payment requests",
			},
		},
		delegate, s.width, s.height,
	)

	listModel.Title = "Tools"
	listModel.Styles.Title = listModel.Styles.Title.
		Background(lipgloss.NoColor{}).
		Foreground(lipgloss.NoColor{}).
		Bold(true).
		Padding(0)

	listModel.SetShowStatusBar(false)
	listModel.SetShowHelp(false)

	// add margin around list
	style := lipgloss.NewStyle().Margin(1, 2)

	return &tools{
		listModel: listModel,
		style:     style,
	}
}

func (m *toolsModel) Init() tea.Cmd {
	return func() tea.Msg {
		return tea.WindowSizeMsg{Width: m.screen.width, Height: m.screen.height}
	}
}

func (m *toolsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.screen.update(msg)
		m.tools.setSize(msg)
	case tea.KeyMsg:
		// only return here if we found a command to execute since the list will
		// handle the rest
		if m, cmd := m.handleKey(msg); cmd != nil {
			return m, cmd
		}
	}

	var cmd tea.Cmd
	m.tools.listModel, cmd = m.tools.listModel.Update(msg)
	return m, cmd
}

func (m *toolsModel) View() string {
	return m.tools.style.Render(m.tools.listModel.View())
}

func (m *toolsModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg.String() {
	case "up", "k":
		// return m.selectPrevious()
	case "down", "j":
		// return m.selectNext()
	case "enter":
		// return m.handleEnter()
	default:
		cmd = handleGlobalKey(msg)
	}
	return m, cmd
}

func (c *tools) setSize(msg tea.WindowSizeMsg) {
	x, y := c.style.GetFrameSize()
	c.listModel.SetSize(msg.Width-x, msg.Height-y)
}
