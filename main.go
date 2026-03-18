package main

import (
	"os"

	"github.com/koki-develop/ghasec/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
