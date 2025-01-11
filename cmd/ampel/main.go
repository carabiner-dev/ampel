package main

import (
	"fmt"

	"github.com/puerco/ampel/internal/cmd"
)

func main() {
	var cmdline = cmd.New()
	if err := cmdline.Execute(); err != nil {
		fmt.Printf("Exec error: %v\n", err)
	}
}
