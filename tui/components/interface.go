package components

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Renderable interface {
	Render() string
}

type Pane interface {
	OnMessage(msg tea.Msg) tea.Cmd
	Render(style lipgloss.Style) string
}
