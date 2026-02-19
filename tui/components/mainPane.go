package components

import (
	tea "github.com/charmbracelet/bubbletea"
)

type MainPane struct {
	selected int
	panes    map[int]Pane
}

var _ Pane = (*MainPane)(nil)

func NewMainPane() *MainPane {
	return &MainPane{
		selected: -1,
		panes: map[int]Pane{
			-1: newSplashPane(),
		},
	}
}

func (p *MainPane) SetSelected(selected int) {
	p.selected = selected
}

func (p *MainPane) OnMessage(msg tea.Msg) tea.Cmd {
	return nil
}

func (p *MainPane) Render() string {
	if pane, ok := p.panes[p.selected]; ok {
		return pane.Render()
	}
	return ""
}
