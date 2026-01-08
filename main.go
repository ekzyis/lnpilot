package main

import (
	"fmt"
	"os"

	"github.com/ekzyis/lnpilot/tui"
)

func main() {
	p := tui.NewProgram()
	if _, err := p.Run(); err != nil {
		fmt.Println("error running program:", err)
		os.Exit(1)
	}
}
