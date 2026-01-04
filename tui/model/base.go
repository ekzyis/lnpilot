package model

import tea "github.com/charmbracelet/bubbletea"

func NewInitialModel() tea.Model {
	return newStartMenuModel()
}

func handleGlobalKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "q", "esc", "ctrl+c":
		return tea.Quit
	}
	return nil
}
