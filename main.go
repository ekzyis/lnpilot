package main

import (
	"fmt"
	"os"

	"github.com/ekzyis/lntutor/tui"
)

func main() {
	p := tui.NewProgram()
	if _, err := p.Run(); err != nil {
		fmt.Println("error running program:", err)
		os.Exit(1)
	}
}
