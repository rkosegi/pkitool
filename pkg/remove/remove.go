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

package remove

import (
	"io"
	"pkitool/pkg/certmgr"
	"pkitool/pkg/common"

	"github.com/spf13/cobra"
)

type removeData struct {
	w     io.Writer
	dir   string
	alias string
}

func remove(d *removeData) error {
	cm := certmgr.New(d.dir)
	return cm.Delete(d.alias)
}

func validate(d *removeData) error {
	if len(d.alias) == 0 {
		return common.ErrAliasMissing
	}
	return nil
}

func NewCommand(w io.Writer) *cobra.Command {
	d := &removeData{
		w:   w,
		dir: ".",
	}
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove certificate and private key corresponding to provided alias",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validate(d)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return remove(d)
		},
	}
	common.AddDirFlag(&d.dir, cmd.Flags())
	cmd.Flags().StringVar(&d.alias, "alias", "", "Alias of certificate to show.")
	return cmd
}
