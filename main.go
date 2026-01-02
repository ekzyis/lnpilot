package main

import (
	"fmt"
	"os"

	"github.com/ekzyis/lntutor/tui"
)

func main() {
	t := tui.New()
	if _, err := t.Run(); err != nil {
		fmt.Println("error running program:", err)
		os.Exit(1)
	}
}
