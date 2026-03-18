package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "ghasec",
}

func Execute() error {
	return rootCmd.Execute()
}
