package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type model struct {
	screen   screen
	selected int
}

type screen struct {
	width  int
	height int
}

func initialModel() model {
	return model{}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.updateScreen(msg)
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m.quit()
		case "up", "k":
			return m.selectPrevious()
		case "down", "j":
			return m.selectNext()
		default:
			return m, nil
		}
	default:
		return m, nil
	}
}

func (m *model) updateScreen(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd) {
	m.screen = screen{width: msg.Width, height: msg.Height}
	return m, nil
}

func (m *model) quit() (tea.Model, tea.Cmd) {
	return m, tea.Quit
}

func (m *model) selectPrevious() (tea.Model, tea.Cmd) {
	if m.selected > 0 {
		m.selected--
	}
	return m, nil
}

func (m *model) selectNext() (tea.Model, tea.Cmd) {
	if m.selected < 1 {
		m.selected++
	}
	return m, nil
}

func (m model) View() string {
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
