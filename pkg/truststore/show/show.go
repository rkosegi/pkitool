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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter/tw"
	tscommon "github.com/rkosegi/pkitool/pkg/truststore/common"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

type certInfo struct {
	Issuer         string   `yaml:"issuer" json:"issuer"`
	Subject        string   `yaml:"subject" json:"subject"`
	CN             string   `yaml:"commonName" json:"commonName"`
	SubjectFN      string   `yaml:"subjectFriendlyName" json:"subjectFriendlyName"`
	IssuerFN       string   `yaml:"issuerFriendlyName" json:"issuerFriendlyName"`
	FpSha1         string   `yaml:"fingerprint_SHA1" json:"fingerprint_SHA1"`
	FpSha256       string   `yaml:"fingerprint_SHA256" json:"fingerprint_SHA256"`
	FpSha1Dotted   string   `yaml:"fingerprint_SHA1_dotted" json:"fingerprint_SHA1_dotted"`
	FpSha256Dotted string   `yaml:"fingerprint_SHA256_dotted" json:"fingerprint_SHA256_dotted"`
	NotAfter       string   `yaml:"notAfter" json:"notAfter"`
	NotBefore      string   `yaml:"notBefore" json:"notBefore"`
	EKUs           []string `yaml:"extendedKeyUsage,omitempty" json:"extendedKeyUsage,omitempty"`
	KeyUsage       []string `yaml:"keyUsage,omitempty" json:"keyUsage,omitempty"`
	IsCA           bool     `yaml:"isCA" json:"isCA"`
	PkAlgo         string   `yaml:"pkAlgo,omitempty" json:"pkAlgo,omitempty"`
	PkSize         int      `yaml:"pkSize,omitempty" json:"pkSize,omitempty"`
	SignatureAlgo  string   `yaml:"signatureAlgo,omitempty" json:"signatureAlgo,omitempty"`
}

type showData struct {
	password string
	format   string
	file     string
	output   string
	cas      []*x509.Certificate
	w        io.Writer
	dfn      tscommon.DecodeFn
	pfn      printerFn
}

type printerFn func([]*certInfo, io.Writer) error

func formatFingerprint(hash []byte) string {
	s := hex.EncodeToString(hash)
	out := ""
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			out += ":"
		}
		out += s[i : i+2]
	}
	return out
}

func keyUsageToString(ku x509.KeyUsage) string {
	if ku&x509.KeyUsageDigitalSignature != 0 {
		return "Digital Signature"
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		return "Content Commitment (Non Repudiation)"
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		return "Key Encipherment"
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		return "Data Encipherment"
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		return "Key Agreement"
	}
	if ku&x509.KeyUsageCertSign != 0 {
		return "Certificate Sign"
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		return "CRL Sign"
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		return "Encipher Only"
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		return "Decipher Only"
	}
	return "N/A"
}

func intTo2PowerComponents(value int) []int {
	var o []int
	for i := 1; i <= 8; i++ {
		if value&(1<<i) != 0 {
			o = append(o, i)
		}
	}
	return o
}

func publicKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {

	case *rsa.PublicKey:
		return pub.N.BitLen()

	case *ecdsa.PublicKey:
		return pub.Params().BitSize

	case ed25519.PublicKey:
		return 256

	default:
		return -1
	}
}

func x509ToCertInfo(cert *x509.Certificate) *certInfo {
	h256 := sha256.Sum256(cert.Raw)
	fpSha256 := hex.EncodeToString(h256[:])

	h1 := sha1.Sum(cert.Raw)
	fpSha1 := hex.EncodeToString(h1[:])

	return &certInfo{
		IsCA:           cert.IsCA,
		PkAlgo:         cert.PublicKeyAlgorithm.String(),
		PkSize:         publicKeySize(cert),
		SignatureAlgo:  cert.SignatureAlgorithm.String(),
		CN:             cert.Subject.CommonName,
		Subject:        cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		SubjectFN:      tscommon.CertFriendlyName(cert.Subject),
		IssuerFN:       tscommon.CertFriendlyName(cert.Issuer),
		FpSha1:         fpSha1,
		FpSha1Dotted:   formatFingerprint(h1[:]),
		FpSha256:       fpSha256,
		FpSha256Dotted: formatFingerprint(h256[:]),
		NotAfter:       cert.NotAfter.Format(time.RFC3339),
		NotBefore:      cert.NotBefore.Format(time.RFC3339),
		EKUs: lo.Map(cert.ExtKeyUsage, func(item x509.ExtKeyUsage, _ int) string {
			return item.String()
		}),
		KeyUsage: lo.Map(intTo2PowerComponents(int(cert.KeyUsage)), func(ku int, _ int) string {
			return keyUsageToString(x509.KeyUsage(ku))
		}),
	}
}

func shortenFingerprint(hashStr string, start, end int) string {
	return hashStr[:start] + "..." + hashStr[len(hashStr)-end:]
}

func tablePrinterFunc(certs []*certInfo, w io.Writer) (err error) {
	tbl := tablewriter.NewTable(w)
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
		"Fingerprint SHA1",
		"Fingerprint SHA256",
	})
	defer func(tbl *tablewriter.Table) {
		_ = tbl.Close()
	}(tbl)

	for _, ca := range certs {
		if err = tbl.Append([]string{
			ca.SubjectFN,
			ca.NotBefore,
			ca.NotAfter,
			shortenFingerprint(ca.FpSha1Dotted, 8, 8),
			shortenFingerprint(ca.FpSha256Dotted, 8, 8),
		}); err != nil {
			return err
		}
	}

	return tbl.Render()

}

func jsonPrinterFunc(certs []*certInfo, w io.Writer) (err error) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(certs)
}

func yamlPrinterFunc(certs []*certInfo, w io.Writer) (err error) {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	return enc.Encode(certs)
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

	cas := lo.Map(d.cas, func(item *x509.Certificate, _ int) *certInfo {
		return x509ToCertInfo(item)
	})
	slices.SortFunc(cas, func(a, b *certInfo) int {
		return strings.Compare(a.SubjectFN, b.SubjectFN)
	})

	return d.pfn(cas, d.w)
}

func New(w io.Writer) *cobra.Command {
	d := &showData{
		password: pkcs12.DefaultPassword,
		format:   "auto",
		output:   "table",
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

 - jks         CA certificates are stored unencrypted and integrity is validated using SHA1.

Supported output formats:

 - table       Basic info in table

 - json        All data in JSON format

 - yaml        All data in YAML format
`,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			if len(d.file) == 0 {
				return tscommon.ErrFileRequired
			}
			if d.dfn, err = tscommon.GetDecoder(d.format, d.file); err != nil {
				return err
			}
			switch d.output {
			case "table":
				d.pfn = tablePrinterFunc
			case "json":
				d.pfn = jsonPrinterFunc
			case "yaml":
				d.pfn = yamlPrinterFunc
			default:
				return fmt.Errorf("unsupported output format: %s", d.output)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return show(d)
		},
	}
	cmd.Flags().StringVar(&d.file, "file", d.file, "path to CA truststore file (required)")
	cmd.Flags().StringVar(&d.password, "password", d.password, "Password to use for decryption")
	cmd.Flags().StringVar(&d.format, "format", d.format, "Input format. One of: [auto|pkcs12|pem-bundle|jks]")
	cmd.Flags().StringVar(&d.output, "output", d.output, "Output format. One of: [table|json|yaml]")
	return cmd
}
