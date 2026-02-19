package components

import tea "github.com/charmbracelet/bubbletea"

type Renderable interface {
	Render() string
}

type Pane interface {
	OnMessage(msg tea.Msg) tea.Cmd
	Render() string
}
