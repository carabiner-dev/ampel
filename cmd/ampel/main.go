package main

import (
	"os"

	"github.com/carabiner-dev/ampel/internal/cmd"
)

func main() {
	cmdline := cmd.New()
	if err := cmdline.Execute(); err != nil {
		os.Exit(1)
	}
}
