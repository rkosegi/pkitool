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

package extract

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"text/template"
	"time"

	sprig "github.com/go-task/slim-sprig"
	tscommon "github.com/rkosegi/pkitool/pkg/truststore/common"
	"github.com/rkosegi/pkitool/pkg/types"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

type exportData struct {
	// CLI args
	only               string
	password           string
	pemFileTemplateStr string
	output             string
	format             string
	file               string

	// runtime data
	w               io.Writer
	decFn           tscommon.DecodeFn
	pemFileTemplate *template.Template
	cas             []*x509.Certificate
	filterRegex     *regexp.Regexp
}

func writeCertToPem(d *exportData, cert *x509.Certificate, filename string) error {
	full := filepath.Join(d.output, filename)
	certPem := new(bytes.Buffer)
	if err := pem.Encode(certPem, &pem.Block{
		Type:  types.BlockTypeCertificate,
		Bytes: cert.Raw,
	}); err != nil {
		return err
	}
	return os.WriteFile(full, certPem.Bytes(), 0644)
}

func renderPemFilename(d *exportData, cert *x509.Certificate) (string, error) {
	var buff bytes.Buffer
	if err := d.pemFileTemplate.Execute(&buff, map[string]interface{}{
		"CN":      cert.Subject.CommonName,
		"FN":      tscommon.CertFriendlyName(cert.Subject),
		"Subject": cert.Subject.String(),
		"Issuer":  cert.Issuer.String(),
	}); err != nil {
		return "", err
	}
	return buff.String(), nil
}

func extract(d *exportData) error {
	var (
		data []byte
		err  error
	)
	start := time.Now()
	fmt.Fprintf(d.w, "Reading store from file %q\n", d.file)
	if data, err = os.ReadFile(d.file); err != nil {
		return err
	}

	if d.cas, err = d.decFn(data, d.password); err != nil {
		return err
	}
	fmt.Fprintf(d.w, "Found %d certificates in the store\n", len(d.cas))
	d.cas = lo.Filter(d.cas, func(cert *x509.Certificate, _ int) bool {
		return d.filterRegex.MatchString(cert.Subject.CommonName)
	})
	fmt.Fprintf(d.w, "In total %d certificates matched expression %q\n", len(d.cas), d.only)
	for _, cert := range d.cas {
		var filename string
		if filename, err = renderPemFilename(d, cert); err != nil {
			return err
		}
		fmt.Fprintf(d.w, "Exporting file %q\n", filename)
		if err = writeCertToPem(d, cert, filename); err != nil {
			return err
		}
	}
	fmt.Fprintf(d.w, "Export completed in %v\n", time.Since(start))
	return nil
}

func New(w io.Writer) *cobra.Command {
	d := &exportData{
		password:           pkcs12.DefaultPassword,
		pemFileTemplateStr: `{{ printf "%s.pem" .FN | replace " " "_" }}`,
		output:             ".",
		format:             "auto",
		w:                  w,
	}
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract one or more CA certificates from truststore",
		Long: `Use this command to extract one or more CA certificates from truststore in PEM format.

Export can be narrowed down to subset of certificates by providing regular expression applied on Common Name.

Supported truststore formats are "pem-bundle" and "pkcs12".
PEM files in destination directory are overwritten, if they already exists.

Output filenames can be customized using Go template, all template functions from https://github.com/go-task/slim-sprig are supported.
Default template is '{{ printf "%s.pem" .FN | replace " " "_" }}'.

Following variables are exposed to template engine:

  🔹 CN - Common name of certificate
  🔹 FN - Friendly name of certificate, this is constructed value, see source in common/common.go
  🔹 Subject - full subject DN
  🔹 Issuer - full issuer DN

Examples:

    🔹pkitool truststore extract --file mystore.p12

      Very minimal - this extracts all CA certs from mystore.p12 using default password "changeit", into current directory

	🔹pkitool truststore extract --file mystore.p12 \
              --password 'mys3cre$' \
              --file-template '{{ .CN }}.crt' \
              --output /tmp/mydir \
              --only 'DigiCert.*G2'

      Using custom password to unlock truststore and extract only DigiCert's G2 certificate(s).
`,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(d.file) == 0 {
				return tscommon.ErrFileRequired
			}

			if d.pemFileTemplate, err = template.New("pem-filename").
				Funcs(sprig.GenericFuncMap()).
				Parse(d.pemFileTemplateStr); err != nil {
				return err
			}
			if len(d.only) == 0 {
				d.only = `.*`
			}
			if d.filterRegex, err = regexp.Compile(d.only); err != nil {
				return err
			}

			if d.decFn, err = tscommon.GetDecoder(d.format, d.file); err != nil {
				return err
			}
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return extract(d)
		},
	}

	cmd.Flags().StringVar(&d.file, "file", d.file, "Name of the file containing the PEM encoded certificate")
	cmd.Flags().StringVar(&d.format, "format", d.format, "Input format of truststore")
	cmd.Flags().StringVar(&d.pemFileTemplateStr, "file-template", d.pemFileTemplateStr, "File template to use for PEM file name")
	cmd.Flags().StringVar(&d.output, "output", d.output, "Output directory")
	cmd.Flags().StringVar(&d.password, "password", d.password, "Password to use for decryption")
	cmd.Flags().StringVar(&d.only, "only", "", "Only extracts certificates whose CN matches provided regular expression")
	return cmd
}
