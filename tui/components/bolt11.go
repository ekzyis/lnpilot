package components

import (
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ekzyis/lnpilot/lightning/bolt11"
)

type bolt11Pane struct {
	textarea   textarea.Model
	invoice    *bolt11.PaymentRequest
	invoiceErr error
}

var _ Pane = (*bolt11Pane)(nil)

func newBolt11Pane() *bolt11Pane {
	const (
		// Width of the textarea. It must be wide enough to not cause layout
		// shift when we render the invoice details.
		width = 90
		lines = 6
	)
	t := textarea.New()
	t.Placeholder = "lnbc..."
	// SetWidth sets visual width, not max characters per line ...
	t.SetWidth(width)
	// ... but t.Width() returns max characters per line
	t.CharLimit = (t.Width() * lines) - 1
	t.SetHeight(lines)
	t.MaxHeight = lines
	t.ShowLineNumbers = false
	t.FocusedStyle.CursorLine = lipgloss.NewStyle()
	t.BlurredStyle.CursorLine = lipgloss.NewStyle()
	// We want to keep the input single-line, so we disable any key that can
	// insert lines. We don't use a textinput because we still want lines to
	// soft wrap.
	t.KeyMap.InsertNewline = key.NewBinding(key.WithDisabled())
	t.Focus()
	return &bolt11Pane{textarea: t}
}

func (p *bolt11Pane) OnMessage(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		msg.Runes = removeWhitespace(msg.Runes)
	}
	p.textarea, cmd = p.textarea.Update(msg)

	value := p.textarea.Value()
	if value == "" {
		p.invoice, p.invoiceErr = nil, nil
	} else {
		p.invoice, p.invoiceErr = bolt11.DecodePaymentRequest(value)
	}

	return cmd
}

func (p *bolt11Pane) Render(style lipgloss.Style) string {
	headerStyle := lipgloss.NewStyle().Bold(true).PaddingBottom(1)
	return style.
		AlignHorizontal(lipgloss.Center).
		Padding(1).
		Render(
			lipgloss.JoinVertical(
				lipgloss.Left,
				headerStyle.Render("bolt11 decoder"),
				p.textarea.View(),
				invoiceDetails(p.invoice, p.invoiceErr),
			),
		)
}

func invoiceDetails(inv *bolt11.PaymentRequest, invErr error) string {
	style := lipgloss.NewStyle().PaddingTop(1)

	if invErr != nil {
		return style.Foreground(lipgloss.Color("1")).Render(invErr.Error())
	}
	if inv == nil {
		return ""
	}

	// TODO: show fields in same order as in invoice
	// TODO: highlight fields
	// TODO: proper columns
	var s strings.Builder
	fmt.Fprintf(&s, "Network: %s\n", inv.Network)
	fmt.Fprintf(&s, "Amount: %d msats\n", inv.Msats)
	fmt.Fprintf(&s, "Timestamp: %s\n", inv.Timestamp)
	fmt.Fprintf(&s, "Payment hash: %x\n", inv.PaymentHash.Bytes())
	if inv.Description != nil {
		fmt.Fprintf(&s, "Description: %s\n", *inv.Description)
	}
	if !inv.DescriptionHash.IsZero() {
		fmt.Fprintf(&s, "Description hash: %x\n", inv.DescriptionHash.Bytes())
	}
	fmt.Fprintf(&s, "Payment secret: %x\n", inv.PaymentSecret.Bytes())
	fmt.Fprintf(&s, "Expiry: %s\n", inv.Timestamp.Add(inv.Expiry))
	fmt.Fprintf(&s, "CLTV delta: %d\n", inv.MinFinalCLTVExpiryDelta)
	if inv.PublicKey != nil {
		fmt.Fprintf(&s, "Public key: %x\n", inv.PublicKey.SerializeCompressed())
	}
	if inv.FallbackAddress != "" {
		fmt.Fprintf(&s, "Fallback address: %s\n", inv.FallbackAddress)
	}
	fmt.Fprintf(&s, "Features:\n")
	for _, bit := range inv.Features.Bits() {
		fmt.Fprintf(&s, "  %02d: %s\n", bit, bit.Name())
	}

	return style.Render(s.String())
}

func removeWhitespace(runes []rune) []rune {
	return slices.DeleteFunc(runes, unicode.IsSpace)
}
