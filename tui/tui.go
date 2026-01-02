package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

func New() *tea.Program {
	return tea.NewProgram(initialModel(), tea.WithAltScreen())
}
