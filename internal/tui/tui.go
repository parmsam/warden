// Package tui provides an interactive terminal UI for browsing secrets,
// audit history, and leases. Launch with `warden tui`.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/parmsam/warden/internal/audit"
	"github.com/parmsam/warden/internal/lease"
	"github.com/parmsam/warden/internal/store"
)

type tabID int

const (
	tabSecrets tabID = iota
	tabAudit
	tabLeases
	numTabs = 3
)

var tabNames = [numTabs]string{"Secrets", "Audit Log", "Leases"}

var (
	subtle    = lipgloss.AdaptiveColor{Light: "241", Dark: "241"}
	highlight = lipgloss.AdaptiveColor{Light: "33", Dark: "86"}
	warn      = lipgloss.AdaptiveColor{Light: "9", Dark: "203"}
	ok        = lipgloss.AdaptiveColor{Light: "2", Dark: "84"}

	activeTabStyle = lipgloss.NewStyle().Bold(true).Foreground(highlight).Padding(0, 1)
	dimTabStyle    = lipgloss.NewStyle().Foreground(subtle).Padding(0, 1)
	tabBarStyle    = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(subtle)
	headerStyle   = lipgloss.NewStyle().Bold(true).Underline(true)
	selectedStyle = lipgloss.NewStyle().Background(lipgloss.AdaptiveColor{Light: "253", Dark: "236"}).Bold(true)
	footerStyle   = lipgloss.NewStyle().Foreground(subtle)
	warnStyle     = lipgloss.NewStyle().Foreground(warn)
	okStyle       = lipgloss.NewStyle().Foreground(ok)
)

type model struct {
	active  tabID
	cursor  int
	width   int
	height  int
	secrets []store.Secret
	entries []audit.Entry
	leases  []lease.Lease
}

// Run launches the full-screen TUI with the provided pre-loaded data.
func Run(secrets []store.Secret, entries []audit.Entry, leases []lease.Lease) error {
	m := model{secrets: secrets, entries: entries, leases: leases}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd { return nil }

func (m model) currentLen() int {
	switch m.active {
	case tabSecrets:
		return len(m.secrets)
	case tabAudit:
		return len(m.entries)
	case tabLeases:
		return len(m.leases)
	}
	return 0
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.active = (m.active + 1) % numTabs
			m.cursor = 0
		case "shift+tab":
			m.active = (m.active + numTabs - 1) % numTabs
			m.cursor = 0
		case "1":
			m.active, m.cursor = tabSecrets, 0
		case "2":
			m.active, m.cursor = tabAudit, 0
		case "3":
			m.active, m.cursor = tabLeases, 0
		case "j", "down":
			if n := m.currentLen(); m.cursor < n-1 {
				m.cursor++
			}
		case "k", "up":
			if m.cursor > 0 {
				m.cursor--
			}
		}
	}
	return m, nil
}

func (m model) View() string {
	if m.width == 0 {
		return "loading…"
	}

	// Tab bar
	tabs := make([]string, numTabs)
	for i, name := range tabNames {
		label := fmt.Sprintf("[%d] %s", i+1, name)
		if tabID(i) == m.active {
			tabs[i] = activeTabStyle.Render(label)
		} else {
			tabs[i] = dimTabStyle.Render(label)
		}
	}
	bar := tabBarStyle.Width(m.width).Render(strings.Join(tabs, "  "))

	// Visible rows = total height minus tab bar (2 lines) and footer (2 lines)
	visibleRows := m.height - 4

	var content string
	switch m.active {
	case tabSecrets:
		content = m.viewSecrets(visibleRows)
	case tabAudit:
		content = m.viewAudit(visibleRows)
	case tabLeases:
		content = m.viewLeases(visibleRows)
	}

	foot := footerStyle.Render("↑↓/jk navigate  tab/1-3 switch tab  q quit")
	return lipgloss.JoinVertical(lipgloss.Left, bar, content, foot)
}

// --- tab views ---------------------------------------------------------------

func (m model) viewSecrets(maxRows int) string {
	if len(m.secrets) == 0 {
		return "\n  No secrets stored. Run 'warden set KEY' to add one."
	}
	widths := []int{26, 28, 20, 20}
	hdr := headerStyle.Render(fmtRow([]string{"KEY", "DESCRIPTION", "CREATED", "LAST ACCESSED"}, widths))
	lines := []string{hdr}

	start := scrollStart(m.cursor, len(m.secrets), maxRows-1)
	for i := start; i < len(m.secrets) && len(lines) < maxRows; i++ {
		sec := m.secrets[i]
		desc := sec.Description
		if desc == "" {
			desc = "—"
		}
		la := "never"
		if sec.LastAccessedAt != nil {
			la = sec.LastAccessedAt.Local().Format("2006-01-02 15:04")
		}
		line := fmtRow([]string{sec.Key, desc, sec.CreatedAt.Local().Format("2006-01-02 15:04"), la}, widths)
		if i == m.cursor {
			line = selectedStyle.Width(m.width).Render(line)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (m model) viewAudit(maxRows int) string {
	if len(m.entries) == 0 {
		return "\n  Audit log is empty."
	}
	widths := []int{20, 12, 26, 6, 0}
	hdr := headerStyle.Render(fmtRow([]string{"TIMESTAMP", "OP", "KEY", "PID", "CWD"}, widths))
	lines := []string{hdr}

	start := scrollStart(m.cursor, len(m.entries), maxRows-1)
	for i := start; i < len(m.entries) && len(lines) < maxRows; i++ {
		e := m.entries[i]
		line := fmtRow([]string{
			e.Timestamp.Local().Format("2006-01-02 15:04:05"),
			e.Operation,
			e.Key,
			fmt.Sprintf("%d", e.PID),
			e.CWD,
		}, widths)
		if i == m.cursor {
			line = selectedStyle.Width(m.width).Render(line)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func (m model) viewLeases(maxRows int) string {
	if len(m.leases) == 0 {
		return "\n  No leases recorded."
	}
	widths := []int{10, 26, 20, 8}
	hdr := headerStyle.Render(fmtRow([]string{"ID", "KEY", "EXPIRES", "STATUS"}, widths))
	lines := []string{hdr}

	now := time.Now()
	start := scrollStart(m.cursor, len(m.leases), maxRows-1)
	for i := start; i < len(m.leases) && len(lines) < maxRows; i++ {
		l := m.leases[i]
		var status string
		switch {
		case l.RevokedAt != nil:
			status = warnStyle.Render("revoked")
		case now.After(l.ExpiresAt):
			status = warnStyle.Render("expired")
		default:
			status = okStyle.Render("active")
		}
		line := fmtRow([]string{
			l.ID[:8],
			l.Key,
			l.ExpiresAt.Local().Format("2006-01-02 15:04"),
			status,
		}, widths)
		if i == m.cursor {
			line = selectedStyle.Width(m.width).Render(line)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// --- helpers -----------------------------------------------------------------

// fmtRow formats values into fixed-width columns. The last column is unbounded.
func fmtRow(values []string, widths []int) string {
	var b strings.Builder
	for i, v := range values {
		w := 0
		if i < len(widths) {
			w = widths[i]
		}
		if w == 0 {
			b.WriteString(v)
			continue
		}
		// Strip ANSI before measuring (lipgloss styles count; raw length misleads)
		plain := lipgloss.NewStyle().Render("") // no-op; use len(v) as approximation
		_ = plain
		if len(v) > w && w > 3 {
			v = v[:w-1] + "…"
		}
		b.WriteString(v)
		if len(v) < w {
			b.WriteString(strings.Repeat(" ", w-len(v)))
		}
	}
	return b.String()
}

// scrollStart returns the first index to render so that cursor is visible.
func scrollStart(cursor, total, visible int) int {
	if total <= visible {
		return 0
	}
	start := cursor - visible + 1
	if start < 0 {
		start = 0
	}
	return start
}
