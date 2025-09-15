/*
Copyright 2024 Richard Kosegi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"io"
	"pkitool/pkg/create"
	"pkitool/pkg/list"
	"pkitool/pkg/remove"
	"pkitool/pkg/show"

	"github.com/spf13/cobra"
)

func New(in io.Reader, out, _ io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Short: "CLI tool to manipulate PKI objects (certificates, private keys) in directory",
		Use:   "pkitool",
	}
	cmd.ResetFlags()
	cmd.AddCommand(create.NewCommand(in, out))
	cmd.AddCommand(show.NewCommand(out))
	cmd.AddCommand(list.NewCommand(out))
	cmd.AddCommand(remove.NewCommand(out))
	return cmd
}
