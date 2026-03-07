package internal

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	Version   string
	Revision  string
	Branch    string
	BuildUser string
	BuildDate string
	GoVersion = runtime.Version()
	GoOS      = runtime.GOOS
	GoArch    = runtime.GOARCH
)

func NewVersionCommand(out io.Writer) *cobra.Command {
	c := &cobra.Command{
		Use:   "version",
		Short: "Display tool version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(out, "Version: %s / %s / %s\n", Version, Branch, Revision)
			fmt.Fprintf(out, "Build by: %s\n", BuildUser)
			fmt.Fprintf(out, "Build at: %s\n", BuildDate)
			fmt.Fprintf(out, "Go : %s / %s / %s\n", GoVersion, GoOS, GoArch)
			return nil
		},
	}
	return c
}
