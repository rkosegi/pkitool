/*
Copyright 2026 Richard Kosegi

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

package truststore

import (
	"io"
	"pkitool/pkg/truststore/assemble"
	"pkitool/pkg/truststore/show"

	"github.com/spf13/cobra"
)

func NewCommand(w io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "truststore",
		Short: "CA truststore operations",
	}
	cmd.AddCommand(assemble.New(w))
	cmd.AddCommand(show.New(w))
	return cmd
}
