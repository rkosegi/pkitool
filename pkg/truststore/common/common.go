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

package common

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/rkosegi/pkitool/pkg/types"
	"software.sslmate.com/src/go-pkcs12"
)

var (
	ErrFileRequired = errors.New("path to the CA truststore is required (--file)")
)

type DecodeFn func(data []byte, password string) ([]*x509.Certificate, error)

func decodePemBundle(data []byte, _ string) (certs []*x509.Certificate, err error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		var cert *x509.Certificate
		if block.Type == types.BlockTypeCertificate {
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

func decodeJks(data []byte, password string) (certs []*x509.Certificate, err error) {
	buff := new(bytes.Buffer)
	buff.Write(data)
	ks := jks.New()
	if err = ks.Load(buff, []byte(password)); err != nil {
		return nil, err
	}
	for _, c := range ks.Aliases() {
		if ks.IsTrustedCertificateEntry(c) {
			var tce jks.TrustedCertificateEntry
			if tce, err = ks.GetTrustedCertificateEntry(c); err != nil {
				return nil, err
			}
			var currentCerts []*x509.Certificate
			if currentCerts, err = x509.ParseCertificates(tce.Certificate.Content); err != nil {
				return nil, err
			}
			certs = append(certs, currentCerts...)
		}
	}
	return certs, nil
}

func autoDetectFormat(filename string) (DecodeFn, error) {
	if strings.HasSuffix(filename, ".pem") {
		return decodePemBundle, nil
	}
	if strings.HasSuffix(filename, ".p12") || strings.HasSuffix(filename, ".pkcs12") {
		return decodePkcs12, nil
	}
	if strings.HasSuffix(filename, ".jks") {
		return decodeJks, nil
	}
	return nil, fmt.Errorf("can't autodetect format from filename: %s", filename)
}

func GetDecoder(format, filename string) (DecodeFn, error) {
	switch format {
	case "jks":
		return decodeJks, nil
	case "pkcs12":
		return decodePkcs12, nil
	case "pem-bundle":
		return decodePemBundle, nil
	default:
		return autoDetectFormat(filename)
	}
}

// CertFriendlyName constructs friendly name by preferring Common Name first, falling back to last RDN component.
func CertFriendlyName(name pkix.Name) string {
	cn := name.CommonName
	if len(cn) > 0 {
		return cn
	}
	rdns := name.ToRDNSequence()
	return fmt.Sprintf("%v", rdns[len(rdns)-1][0].Value)
}
