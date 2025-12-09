package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Println("error running program:", err)
		os.Exit(1)
	}
}

func initialModel() model {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(lightningColor)
	return model{spinner: s}
}

type model struct {
	spinner spinner.Model
	screen  screen
}

type screen struct {
	width  int
	height int
}

var (
	lightningColor = lipgloss.Color("#fada5e")
	mutedColor     = lipgloss.Color("#707070")
)

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.screen = screen{width: msg.Width, height: msg.Height}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		default:
			return m, nil
		}

	default:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
}

func (m model) View() string {
	return lipgloss.NewStyle().
		Width(m.screen.width).
		Height(m.screen.height).
		AlignHorizontal(lipgloss.Center).
		AlignVertical(lipgloss.Center).
		Render(
			fmt.Sprintf("%s setting up your lightning node ...\n", m.spinner.View()),
			lipgloss.NewStyle().
				Padding(1).
				Foreground(mutedColor).
				Render("press q to quit"),
		)
}
