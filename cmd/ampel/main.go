package main

import (
	"fmt"

	"github.com/carabiner-dev/ampel/internal/cmd"
)

func main() {
	cmdline := cmd.New()
	if err := cmdline.Execute(); err != nil {
		fmt.Printf("Exec error: %v\n", err)
	}
}
