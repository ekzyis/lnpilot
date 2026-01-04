package model

import (
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type chapterModel struct {
	screen
	chapters *chapters
	selected int
}

type chapters struct {
	listModel list.Model
	style     lipgloss.Style
}

type chapter struct {
	title, desc string
}

var _ tea.Model = (*chapterModel)(nil)

func (i chapter) Title() string       { return i.title }
func (i chapter) Description() string { return i.desc }
func (i chapter) FilterValue() string { return i.title }

func newChapterModel(s screen) (tea.Model, tea.Cmd) {
	m := &chapterModel{
		screen:   s,
		selected: 0,
		chapters: newChapters(s),
	}
	return m, m.Init()
}

func newChapters(s screen) *chapters {
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = delegate.Styles.SelectedTitle.
		BorderForeground(lightningColor).
		Foreground(lightningColor)
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedDesc.
		BorderForeground(lightningColor).
		Foreground(lightningColor)

	listModel := list.New(
		[]list.Item{
			chapter{
				title: "bolt11",
				desc:  "everything about lightning invoices",
			},
			chapter{
				title: "secp256k1",
				desc:  "learn about digital signatures with the secp256k1 curve",
			},
		},
		delegate, s.width, s.height,
	)

	listModel.Title = "Chapters"
	listModel.Styles.Title = listModel.Styles.Title.
		Background(lipgloss.NoColor{}).
		Foreground(lipgloss.NoColor{}).
		Bold(true).
		Padding(0)

	listModel.SetShowStatusBar(false)
	listModel.SetShowHelp(false)

	// add margin around list
	style := lipgloss.NewStyle().Margin(1, 2)

	return &chapters{
		listModel: listModel,
		style:     style,
	}
}

func (m *chapterModel) Init() tea.Cmd {
	return func() tea.Msg {
		return tea.WindowSizeMsg{Width: m.screen.width, Height: m.screen.height}
	}
}

func (m *chapterModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.screen.update(msg)
		m.chapters.setSize(msg)
	case tea.KeyMsg:
		// only return here if we found a command to execute since the list will
		// handle the rest
		if m, cmd := m.handleKey(msg); cmd != nil {
			return m, cmd
		}
	}

	var cmd tea.Cmd
	m.chapters.listModel, cmd = m.chapters.listModel.Update(msg)
	return m, cmd
}

func (m *chapterModel) View() string {
	return m.chapters.style.Render(m.chapters.listModel.View())
}

func (m *chapterModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg.String() {
	case "up", "k":
		// return m.selectPrevious()
	case "down", "j":
		// return m.selectNext()
	case "enter":
		// return m.handleEnter()
	default:
		cmd = handleGlobalKey(msg)
	}
	return m, cmd
}

func (c *chapters) setSize(msg tea.WindowSizeMsg) {
	x, y := c.style.GetFrameSize()
	c.listModel.SetSize(msg.Width-x, msg.Height-y)
}
