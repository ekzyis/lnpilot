package model

import tea "github.com/charmbracelet/bubbletea"

type screen struct {
	width  int
	height int
}

func (s *screen) update(msg tea.WindowSizeMsg) tea.Cmd {
	s.width = msg.Width
	s.height = msg.Height
	return nil
}
