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
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"pkitool/pkg/common"
	"strings"
	"time"

	"github.com/olekukonko/errors"
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
	dfn      decodeFn
}

type decodeFn func(data []byte, password string) ([]*x509.Certificate, error)

func decodePemBundle(data []byte, _ string) (certs []*x509.Certificate, err error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		var cert *x509.Certificate
		if block.Type == common.BlockTypeCertificate {
			if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func decodePkcs12(data []byte, password string) (certs []*x509.Certificate, err error) {
	return pkcs12.DecodeTrustStore(data, password)
}

func autoDetectFormat(filename string) (decodeFn, error) {
	if strings.HasSuffix(filename, ".pem") {
		return decodePemBundle, nil
	}
	if strings.HasSuffix(filename, ".p12") || strings.HasSuffix(filename, ".pkcs12") {
		return decodePkcs12, nil
	}
	return nil, fmt.Errorf("can't autodetect format: %s", filename)
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

	tbl := tablewriter.NewTable(d.w, tablewriter.WithHeader([]string{
		"Common name", "Valid From", "Valid To",
	}))
	defer func(tbl *tablewriter.Table) {
		_ = tbl.Close()
	}(tbl)

	for _, ca := range d.cas {
		if err = tbl.Append([]string{
			ca.Subject.CommonName,
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
				return errors.New("Path to the CA truststore is required (--file)")
			}
			switch d.format {
			case "pkcs12":
				d.dfn = decodePkcs12
			case "pem-bundle":
				d.dfn = decodePemBundle
			default:
				if d.dfn, err = autoDetectFormat(d.file); err != nil {
					return err
				}
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
