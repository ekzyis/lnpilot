package model

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type startModel struct {
	screen
	selected int
}

var _ tea.Model = (*startModel)(nil)

func newStartMenuModel() tea.Model {
	return &startModel{
		screen: screen{
			width:  0,
			height: 0,
		},
		selected: 0,
	}
}

func (m *startModel) Init() tea.Cmd {
	return nil
}

func (m *startModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.screen.update(msg)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *startModel) View() string {
	return lipgloss.NewStyle().
		Width(m.screen.width).
		Height(m.screen.height).
		AlignHorizontal(lipgloss.Center).
		AlignVertical(lipgloss.Center).
		Render(
			fmt.Sprintf("%s\n", Banner),
			menu(m.selected),
			lipgloss.NewStyle().
				Padding(1).
				Foreground(mutedColor).
				Render("press q to quit"),
		)
}

func (m *startModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg.String() {
	case "up", "k":
		return m.selectPrevious()
	case "down", "j":
		return m.selectNext()
	case "enter":
		return m.handleEnter()
	default:
		cmd = handleGlobalKey(msg)
	}
	return m, cmd
}

func menu(selected int) string {
	buttons := []string{"New Node", "Load Node"}
	buttonStyle := lipgloss.NewStyle().Margin(1, 0)

	buttonViews := make([]string, len(buttons))
	for i, btn := range buttons {
		if i == selected {
			buttonViews[i] = buttonStyle.Bold(true).Render(">", btn)
		} else {
			buttonViews[i] = buttonStyle.Render(" ", btn)
		}
	}

	return lipgloss.NewStyle().
		Padding(1).
		Align(lipgloss.Center).
		Render(
			lipgloss.JoinVertical(
				lipgloss.Left,
				buttonViews...,
			),
		)
}

func (m *startModel) selectPrevious() (tea.Model, tea.Cmd) {
	if m.selected > 0 {
		m.selected--
	}
	return m, nil
}

func (m *startModel) selectNext() (tea.Model, tea.Cmd) {
	if m.selected < 1 {
		m.selected++
	}
	return m, nil
}

func (m *startModel) handleEnter() (tea.Model, tea.Cmd) {
	switch m.selected {
	case 0:
		return m.newNode()
	case 1:
		return m.loadNode()
	default:
		return m, nil
	}
}

func (m *startModel) newNode() (tea.Model, tea.Cmd) {
	return newToolsModel(m.screen)
}

func (m *startModel) loadNode() (tea.Model, tea.Cmd) {
	return m, nil
}
