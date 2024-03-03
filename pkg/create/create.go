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

package create

import (
	"crypto/x509/pkix"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io"
	"net"
	"pkitool/pkg/certmgr"
	"pkitool/pkg/common"
)

type commonCreateData struct {
	w          io.Writer
	alias      string
	parent     string
	validYears int
	subject    pkix.Name
	issuer     pkix.Name
	bits       int
	dir        string
	serial     int64
}

type createLeafData struct {
	commonCreateData
	ipSan  []net.IP
	dnsSan []string
}

type createCaData struct {
	commonCreateData
	imCA bool
}

func createCA(d *createCaData) error {
	cm := certmgr.New(d.dir)
	cd := &certmgr.CertData{
		KeySize:     d.bits,
		ValidYears:  d.validYears,
		Alias:       d.alias,
		ParentAlias: d.parent,
		Issuer:      d.issuer,
		Subject:     d.subject,
		Serial:      d.serial,
	}
	if d.imCA {
		return cm.NewIntermediateCA(cd)
	} else {
		return cm.NewRootCA(cd)
	}
}

func createLeaf(d *createLeafData) error {
	cm := certmgr.New(d.dir)
	cd := &certmgr.CertData{
		KeySize:     d.bits,
		ValidYears:  d.validYears,
		IPSan:       d.ipSan,
		DNSSan:      d.dnsSan,
		Alias:       d.alias,
		ParentAlias: d.parent,
		Issuer:      d.issuer,
		Subject:     d.subject,
		Serial:      d.serial,
	}
	return cm.NewLeaf(cd)
}

func addDnFlags(prefix string, pm *pkix.Name, pf *pflag.FlagSet, helpSuffix string) {
	pf.StringArrayVar(&pm.Locality, prefix+"-locality", pm.Country, "Locality components of "+prefix+" DN."+helpSuffix)
	pf.StringArrayVar(&pm.Province, prefix+"-province", pm.Province, "Province components of "+prefix+" DN."+helpSuffix)
	pf.StringArrayVar(&pm.Country, prefix+"-country", pm.Country, "Country components of "+prefix+" DN."+helpSuffix)
	pf.StringArrayVar(&pm.StreetAddress, prefix+"-street-address", pm.StreetAddress, "Street address components of "+prefix+" DN."+helpSuffix)
	pf.StringArrayVar(&pm.PostalCode, prefix+"-postal-code", pm.PostalCode, "Postal code components of "+prefix+" DN."+helpSuffix)
	pf.StringArrayVar(&pm.Organization, prefix+"-organization", pm.Organization, "Organization components of "+prefix+" DN."+helpSuffix)
	pf.StringArrayVar(&pm.OrganizationalUnit, prefix+"-organizational-unit", pm.OrganizationalUnit, "Organizational unit components of "+prefix+" DN."+helpSuffix)
	pf.StringVar(&pm.CommonName, prefix+"-common-name", pm.CommonName, "Common name components of "+prefix+" DN."+helpSuffix)
}

func addCommonFlags(d *commonCreateData, pf *pflag.FlagSet) {
	pf.Int64Var(&d.serial, "serial", d.serial, "Certificate serial number")
	pf.IntVar(&d.bits, "bits", d.bits, "Key size (bits), like 2048 or 4096.")
	pf.StringVar(&d.alias, "alias", "", "Alias for new certificate. Must be unique within directory")
	pf.IntVar(&d.validYears, "years", d.validYears, "How meany years should new certificate be valid for")
	common.AddDirFlag(&d.dir, pf)
}

func validateCa(d *createCaData) error {
	if !d.imCA {
		if len(d.issuer.String()) == 0 {
			d.issuer = d.subject
		}
	}
	return nil
}

func newCaSubCommand(w io.Writer) *cobra.Command {
	d := &createCaData{
		commonCreateData: commonCreateData{
			w:          w,
			bits:       4096,
			dir:        ".",
			validYears: 2,
		},
	}
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Create new CA certificate/private key pair",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateCa(d)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return createCA(d)
		},
	}
	cmd.Flags().StringVar(&d.parent, "parent", "", "Alias of parent (issuing) CA certificate. Only taken into account for intermediate CA")
	cmd.Flags().BoolVar(&d.imCA, "intermediate", d.imCA, "Whether new CA is intermediate")
	addCommonFlags(&d.commonCreateData, cmd.Flags())
	addDnFlags("issuer", &d.issuer, cmd.Flags(), " Only taken into account for root CA")
	addDnFlags("subject", &d.subject, cmd.Flags(), "")
	return cmd
}

func newLeafSubCommand(w io.Writer) *cobra.Command {
	d := &createLeafData{
		commonCreateData: commonCreateData{
			w:          w,
			bits:       4096,
			dir:        ".",
			validYears: 2,
		},
	}
	cmd := &cobra.Command{
		Use:   "leaf",
		Short: "Create new leaf certificate/private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return createLeaf(d)
		},
	}
	addCommonFlags(&d.commonCreateData, cmd.Flags())
	addDnFlags("subject", &d.subject, cmd.Flags(), "")
	cmd.Flags().StringVar(&d.parent, "parent", "", "Alias of parent (issuing) CA certificate")
	cmd.Flags().IPSliceVar(&d.ipSan, "ip-san", d.ipSan, "Optional IP subject alternative name")
	cmd.Flags().StringArrayVar(&d.dnsSan, "dns-san", d.dnsSan, "Optional DNS subject alternative name")
	return cmd
}

func NewCommand(_ io.Reader, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create new certificate",
	}
	cmd.AddCommand(newCaSubCommand(out))
	cmd.AddCommand(newLeafSubCommand(out))
	return cmd
}
