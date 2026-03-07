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

package assemble

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"pkitool/pkg/common"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

var (
	supportedFormats = []string{"pkcs12", "pem-bundle"}
)

type data struct {
	start     time.Time
	certs     []*x509.Certificate
	certFiles []string

	format string

	pkcs21EncName string
	pkcs12Enc     *pkcs12.Encoder
	encFunc       func([]*x509.Certificate, string) ([]byte, error)

	output   string
	password string
}

func loadPEMs(certFiles []string) ([]*x509.Certificate, error) {
	var res []*x509.Certificate
	for _, file := range certFiles {
		pemBytes, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != common.BlockTypeCertificate {
			return nil, fmt.Errorf("can't load CA certificate from %q", file)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("can't parse CA certificate from %q: %w", file, err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("certificate is not a CA: %v", cert.Subject)
		}
		res = append(res, cert)
	}
	return res, nil
}

func bundlePEMs(certificates []*x509.Certificate, _ string) ([]byte, error) {
	var (
		res bytes.Buffer
		err error
	)

	for _, cert := range certificates {
		certPem := new(bytes.Buffer)
		if err = pem.Encode(certPem, &pem.Block{
			Type:  common.BlockTypeCertificate,
			Bytes: cert.Raw,
		}); err != nil {
			return nil, err
		}
		if _, err = res.Write(certPem.Bytes()); err != nil {
			return nil, err
		}
	}
	return res.Bytes(), nil
}

func New(w io.Writer) *cobra.Command {
	d := &data{
		pkcs21EncName: "compatible",
		password:      pkcs12.DefaultPassword,
		format:        "pkcs12",
	}
	cmd := &cobra.Command{
		Use:   "assemble",
		Short: "Assemble CA truststore from list of CRT/PEM files",
		Long: `This command can be used create truststore from provided list of CRT/PEM files.

Supported output formats:

 - pkcs12      Certificates are encrypted using provided PKCS12 encoding and password (see below).

 - pem-bundle  All certificates are concatenated into single file. This is similar to command "cat *.crt > bundle.pem".
               Password is ignored as there is no encryption involved.

JKS is not supported.

Supported PKCS12 encodings (--pkcs12-encoding):

 - legacy      Certificates are encrypted using PBE with RC2, and keys are encrypted using PBE with 3DES,
               using keys derived with 2048 iterations of HMAC-SHA-1.
               MACs use HMAC-SHA-1 with keys derived with 1 iteration of HMAC-SHA-1.

 - compatible  This is the default. Certificates and keys are encrypted using PBE with 3DES,
               using keys derived with 2048 iterations of HMAC-SHA-1.
               MACs use HMAC-SHA-1 with keys derived with 1 iteration of HMAC-SHA-1.

 - modern      Certificates are encrypted using PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC.
               The MAC algorithm is HMAC-SHA-2.

Note: PKCS12 implementation is based on https://github.com/SSLMate/go-pkcs12
`,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			d.start = time.Now()
			if d.output == "" {
				return fmt.Errorf("no output file provided (--output)")
			}
			fmt.Fprintf(w, "Will write output to %q\n", d.output)
			if len(d.certFiles) == 0 {
				return fmt.Errorf("no CRT/PEM files provided (--pem)")
			}
			if !slices.Contains(supportedFormats, d.format) {
				return fmt.Errorf("unsupported format: %q, use one of %v", d.format,
					strings.Join(supportedFormats, ", "))
			}
			fmt.Fprintf(w, "Using format %q\n", d.format)
			switch d.format {
			case "pkcs12":
				switch d.pkcs21EncName {
				case "legacy":
					d.encFunc = pkcs12.LegacyRC2.EncodeTrustStore
				case "compatible":
					d.encFunc = pkcs12.LegacyDES.EncodeTrustStore
				case "modern":
					d.encFunc = pkcs12.Modern.EncodeTrustStore
				default:
					return fmt.Errorf("unknown PKCS12 encoding %q", d.pkcs21EncName)
				}
				fmt.Fprintf(w, "Using PKCS12 encoding %q\n", d.pkcs21EncName)
			case "pem-bundle":
				d.encFunc = bundlePEMs
				return nil
			default:
				return fmt.Errorf("unsupported format: %q, use one of %v", d.format,
					strings.Join(supportedFormats, ", "))
			}
			fmt.Fprintf(w, "Loading PEM files: %s\n", strings.Join(d.certFiles, ", "))
			d.certs, err = loadPEMs(d.certFiles)
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				tsContent []byte
				err       error
			)
			if tsContent, err = d.encFunc(d.certs, d.password); err != nil {
				return err
			}
			return os.WriteFile(d.output, tsContent, 0644)
		},
		PostRunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(w, "Truststore assembled in %v\n", time.Since(d.start))
			return nil
		},
	}

	cmd.Flags().StringVar(&d.output, "output", d.output, "Output file")
	cmd.Flags().StringVar(&d.format, "format", d.format, "Output format (pkcs12/pem-bundle)")
	cmd.Flags().StringSliceVar(&d.certFiles, "pem", []string{}, "CRT/PEM file to include in the truststore")
	cmd.Flags().StringVar(&d.pkcs21EncName, "pkcs12-encoding", d.pkcs21EncName, "Name of the PKCS12 encoding to use (legacy/compatible/modern)")
	cmd.Flags().StringVar(&d.password, "password", d.password, "Password to use for encryption")
	return cmd
}
