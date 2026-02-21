package components

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ekzyis/lnpilot/tui/color"
)

type SidePane struct {
	items         []item
	width, height int
	selected      int
}

type item struct {
	title    string
	subtitle string
}

var _ Pane = (*SidePane)(nil)

func NewSidePane() *SidePane {
	items := []item{
		{"bolt11", "decode payment requests"},
	}
	return &SidePane{
		items:    items,
		width:    0,
		height:   0,
		selected: -1,
	}
}

func (p *SidePane) SetSize(width, height int) {
	p.width = width
	p.height = height
}

func (p *SidePane) Selected() int {
	return p.selected
}

func (p *SidePane) OnMessage(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if p.selected > 0 {
				p.selected--
			}
		case "down", "j":
			if p.selected < len(p.items)-1 {
				p.selected++
			}
		}
	}
	return nil
}

func (p *SidePane) Render(style lipgloss.Style) string {
	var (
		headerStyle = lipgloss.NewStyle().Bold(true).PaddingBottom(1)
		content     []string
	)

	content = append(content, headerStyle.Render("flight controls"))
	for i, item := range p.items {
		content = append(content, item.render(i == p.selected))
	}

	return style.
		Padding(1).
		Render(
			lipgloss.JoinVertical(
				lipgloss.Left,
				content...,
			),
		)
}

func (i *item) render(selected bool) string {
	textStyle := lipgloss.NewStyle().PaddingLeft(1)
	itemStyle := lipgloss.NewStyle().
		BorderLeft(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(color.Muted).
		MarginBottom(1)

	if selected {
		textStyle = textStyle.Foreground(color.Lightning)
		itemStyle = itemStyle.BorderForeground(color.Lightning)
	}

	return itemStyle.Render(
		lipgloss.JoinVertical(
			lipgloss.Left,
			textStyle.Bold(true).Render(i.title),
			textStyle.Render(i.subtitle),
		),
	)
}
