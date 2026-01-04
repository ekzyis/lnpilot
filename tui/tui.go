package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/ekzyis/lntutor/tui/model"
)

func NewProgram() *tea.Program {
	return tea.NewProgram(
		model.NewInitialModel(),
		tea.WithAltScreen(),
	)
}
