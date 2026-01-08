package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/ekzyis/lnpilot/tui/model"
)

func NewProgram() *tea.Program {
	return tea.NewProgram(
		model.NewInitialModel(),
		tea.WithAltScreen(),
	)
}
