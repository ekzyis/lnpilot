package log

import (
	"fmt"
	"log"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	f *os.File
)

func init() {
	var err error
	f, err = tea.LogToFile("debug.log", "debug")
	if err != nil {
		log.Fatalf("error opening debug.log: %v", err)
	}
}

func Logf(format string, a ...any) {
	if f != nil {
		fmt.Fprintf(f, format, a...)
	}
}
