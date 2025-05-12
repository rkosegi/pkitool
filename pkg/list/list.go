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

package list

import (
	"io"
	"pkitool/pkg/certmgr"
	"pkitool/pkg/common"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

type listData struct {
	w   io.Writer
	dir string
}

func list(d *listData) error {
	cm := certmgr.New(d.dir)
	ents, err := cm.List()
	if err != nil {
		return err
	}
	tbl := tablewriter.NewWriter(d.w)
	tbl.Header([]string{
		"Subject", "Issuer", "Valid to",
	})
	for _, ent := range ents {
		ch, err := cm.Get(ent)
		if err != nil {
			return err
		}
		_ = tbl.Append([]string{
			ch.Cert.Subject.String(),
			ch.Cert.Issuer.String(),
			ch.Cert.NotAfter.String(),
		})
	}
	return tbl.Render()
}

func NewCommand(w io.Writer) *cobra.Command {
	d := &listData{
		w:   w,
		dir: ".",
	}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all certificates in given directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			return list(d)
		},
	}
	common.AddDirFlag(&d.dir, cmd.Flags())
	return cmd
}
