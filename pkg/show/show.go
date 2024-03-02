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

package show

import (
	"crypto/x509"
	"github.com/olekukonko/tablewriter"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"io"
	"pkitool/pkg/certmgr"
	"pkitool/pkg/common"
	"slices"
	"strconv"
	"strings"
)

type propValueGetter func(*certmgr.PairHolder) string

type showData struct {
	w     io.Writer
	alias string
	dir   string
	tree  bool
}

var (
	kuMap = map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature: "KeyUsageDigitalSignature",
		x509.KeyUsageDataEncipherment: "KeyUsageDataEncipherment",
		x509.KeyUsageCertSign:         "KeyUsageCertSign",
		x509.KeyUsageCRLSign:          "KeyUsageCRLSign",
	}
	ekuMap = map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageClientAuth:      "ExtKeyUsageClientAuth",
		x509.ExtKeyUsageServerAuth:      "ExtKeyUsageServerAuth",
		x509.ExtKeyUsageCodeSigning:     "ExtKeyUsageCodeSigning",
		x509.ExtKeyUsageTimeStamping:    "ExtKeyUsageTimeStamping",
		x509.ExtKeyUsageEmailProtection: "ExtKeyUsageEmailProtection",
		x509.ExtKeyUsageAny:             "ExtKeyUsageAny",
	}
	props = map[string]propValueGetter{
		"Subject": func(holder *certmgr.PairHolder) string {
			return holder.Cert.Subject.String()
		},
		"Issuer": func(holder *certmgr.PairHolder) string {
			return holder.Cert.Issuer.String()
		},
		"Valid from": func(holder *certmgr.PairHolder) string {
			return holder.Cert.NotBefore.String()
		},
		"Valid to": func(holder *certmgr.PairHolder) string {
			return holder.Cert.NotAfter.String()
		},
		"Is CA?": func(holder *certmgr.PairHolder) string {
			return strconv.FormatBool(holder.Cert.IsCA)
		},
		"Basic constraints valid?": func(holder *certmgr.PairHolder) string {
			return strconv.FormatBool(holder.Cert.BasicConstraintsValid)
		},
		"Serial": func(holder *certmgr.PairHolder) string {
			if holder.Cert.SerialNumber != nil {
				return holder.Cert.SerialNumber.String()
			} else {
				return "N/A"
			}
		},
		"Public exponent": func(holder *certmgr.PairHolder) string {
			return strconv.Itoa(holder.Key.E)
		},
		"Key usage": func(holder *certmgr.PairHolder) string {
			return strings.Join(
				lo.FilterMap(
					lo.Keys(kuMap), func(item x509.KeyUsage, _ int) (string, bool) {
						if item&holder.Cert.KeyUsage == item {
							return kuMap[item], true
						}
						return "", false
					}), ",")
		},
		"Ext. key usage": func(holder *certmgr.PairHolder) string {
			return strings.Join(
				lo.FilterMap(
					lo.Keys(ekuMap), func(item x509.ExtKeyUsage, _ int) (string, bool) {
						if lo.Contains(holder.Cert.ExtKeyUsage, item) {
							return ekuMap[item], true
						}
						return "", false
					}), ",")
		},
	}
)

func NewCommand(w io.Writer) *cobra.Command {
	d := &showData{
		w:    w,
		dir:  ".",
		tree: false,
	}
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show details about certificate/private key pair",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validate(d)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return show(d)
		},
	}
	cmd.Flags().StringVar(&d.alias, "alias", "", "Alias of certificate to show.")
	cmd.Flags().BoolVar(&d.tree, "tree", d.tree, "Whether to display information as a tree")
	common.AddDirFlag(&d.dir, cmd.Flags())
	return cmd
}

func validate(d *showData) error {
	if len(d.alias) == 0 {
		return common.ErrAliasMissing
	}
	return nil
}

func showTable(ph *certmgr.PairHolder, w io.Writer) {
	tbl := tablewriter.NewWriter(w)
	tbl.SetHeader([]string{
		"Property", "Value",
	})
	tbl.SetAlignment(tablewriter.ALIGN_LEFT)
	propKeys := lo.Keys(props)
	slices.Sort(propKeys)
	for _, e := range propKeys {
		tbl.Append([]string{e, props[e](ph)})
	}
	tbl.Render()
}

func show(d *showData) error {
	cm := certmgr.New(d.dir)
	ph, err := cm.Get(d.alias)
	if err != nil {
		return err
	}
	showTable(ph, d.w)
	return nil
}
