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

package show

import (
	"crypto/x509"
	"io"
	"os"
	"time"

	"github.com/olekukonko/tablewriter/tw"
	tscommon "github.com/rkosegi/pkitool/pkg/truststore/common"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

type showData struct {
	password string
	format   string
	file     string
	cas      []*x509.Certificate
	w        io.Writer
	dfn      tscommon.DecodeFn
}

func show(d *showData) error {
	var (
		data []byte
		err  error
	)

	if data, err = os.ReadFile(d.file); err != nil {
		return err
	}

	if d.cas, err = d.dfn(data, d.password); err != nil {
		return err
	}

	tbl := tablewriter.NewTable(d.w)
	tbl.Configure(func(cfg *tablewriter.Config) {
		cfg.Header.Formatting = tw.CellFormatting{
			AutoFormat: tw.Off,
			AutoWrap:   tw.WrapNone,
		}
	})
	tbl.Header([]string{
		"Subject friendly name",
		"Valid From",
		"Valid To",
	})
	defer func(tbl *tablewriter.Table) {
		_ = tbl.Close()
	}(tbl)

	for _, ca := range d.cas {
		if err = tbl.Append([]string{
			tscommon.CertFriendlyName(ca.Subject),
			ca.NotBefore.Format(time.RFC3339),
			ca.NotAfter.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}

	return tbl.Render()
}

func New(w io.Writer) *cobra.Command {
	d := &showData{
		password: pkcs12.DefaultPassword,
		format:   "auto",
		w:        w,
	}
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show contents of CA truststore",
		Long: `This command can be used to display content of the truststore.

Supported input formats:

 - pkcs12      Certificates are decrypted using provided password (see below).

 - pem-bundle  File is just a bunch of PEM files concatenated together.
               Password is ignored as there is no encryption involved.

JKS is not supported.
`,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(d.file) == 0 {
				return tscommon.ErrFileRequired
			}
			if d.dfn, err = tscommon.GetDecoder(d.format, d.file); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return show(d)
		},
	}
	cmd.Flags().StringVar(&d.file, "file", d.file, "path to CA truststore file (required)")
	cmd.Flags().StringVar(&d.password, "password", d.password, "Password to use for decryption")
	cmd.Flags().StringVar(&d.format, "format", d.format, "Output format. One of: [auto|pkcs12|pem-bundle]")
	return cmd
}
