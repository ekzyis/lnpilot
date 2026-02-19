package components

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ekzyis/lnpilot/tui/color"
)

const (
	banner = "" +
		`   __          _ __     __ ` + "\n" +
		`  / /__  ___  (_) /__  / /_` + "\n" +
		` / / _ \/ _ \/ / / _ \/ __/` + "\n" +
		`/_/_//_/ .__/_/_/\___/\__/ ` + "\n" +
		`      /_/                  `
)

type splashPane struct{}

var _ Pane = (*splashPane)(nil)

func newSplashPane() *splashPane {
	return &splashPane{}
}

func (p *splashPane) OnMessage(msg tea.Msg) tea.Cmd {
	return nil
}

func (p *splashPane) Render() string {
	return lipgloss.JoinVertical(
		lipgloss.Center,
		banner,
		lipgloss.NewStyle().
			PaddingTop(1).
			Render("your lightning node cockpit"),
		lipgloss.NewStyle().
			Foreground(color.Muted).
			Padding(1).
			// TODO: 'press :q to quit'
			Render("press q to quit"),
	)
}
