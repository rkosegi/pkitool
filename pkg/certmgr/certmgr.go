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

package certmgr

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/samber/lo"
)

const (
	typeCert          = "CERTIFICATE"
	typeRsaPrivateKey = "RSA PRIVATE KEY"
)

type Interface interface {
	NewRootCA(cd *CertData) error
	NewIntermediateCA(cd *CertData) error
	// NewLeaf creates new leaf certificate and private key
	NewLeaf(cd *CertData) error
	// List lists all aliases.
	List() ([]string, error)
	// Delete removes both certificate and private key file corresponding to given alias.
	// Ignore any "not found" errors.
	Delete(alias string) error
	// Get gets both certificate and private key for given alias.
	Get(alias string) (*PairHolder, error)
}

// PairHolder is structure to wrap both certificate and corresponding private key
type PairHolder struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

type certMgr struct {
	// root directory where certificates and private keys are stored
	dir string
}

// aliasToFile
func (cm *certMgr) aliasToFile(alias string, private bool) string {
	suffix := "pem"
	if private {
		suffix = "key"
	}
	return fmt.Sprintf("%s/%s.%s", cm.dir, alias, suffix)
}

// doesAliasFileExist checks if given alias resolves into existing file.
func (cm *certMgr) doesAliasFileExist(alias string, private bool) bool {
	if _, err := os.Stat(cm.aliasToFile(alias, private)); err != nil {
		return !os.IsNotExist(err)
	}
	return true
}

// isAliasFilename checks if provided filename is valid file for alias.
// it could be either private key file (.key) or certificate file (.pem).
func (cm *certMgr) isAliasFilename(file string) bool {
	return strings.HasSuffix(file, ".pem") || strings.HasSuffix(file, ".key")
}

// fileToAlias extracts alias from filename.
// No checks are done here, it's expected that isAliasFile was called before using this function.
func (cm *certMgr) fileToAlias(file string) string {
	return file[0 : len(file)-4]
}

func (cm *certMgr) Delete(alias string) error {
	err := os.Remove(cm.aliasToFile(alias, true))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	err = os.Remove(cm.aliasToFile(alias, false))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (cm *certMgr) List() ([]string, error) {
	entries, err := os.ReadDir(cm.dir)
	if err != nil {
		return nil, err
	}
	return lo.Uniq(lo.Map(lo.Filter(entries, func(entry os.DirEntry, _ int) bool {
		return cm.isAliasFilename(entry.Name())
	}), func(item os.DirEntry, _ int) string {
		return cm.fileToAlias(item.Name())
	}),
	), nil
}

func (cm *certMgr) Get(alias string) (*PairHolder, error) {
	return cm.load(alias)
}

type CertData struct {
	KeySize     int
	ValidYears  int
	IPSan       []net.IP
	DNSSan      []string
	Alias       string
	ParentAlias string
	SelfSigned  bool
	IsCA        bool
	Issuer      pkix.Name
	Subject     pkix.Name
	Serial      int64
}

func (cm *certMgr) NewRootCA(cd *CertData) error {
	if err := check(cd,
		requireSubject(),
		requireAlias(),
		validAtLeastYears(1)); err != nil {
		return err
	}
	cd.SelfSigned = true
	cd.IsCA = true
	return cm.create(cd)
}

func (cm *certMgr) NewIntermediateCA(cd *CertData) error {
	if err := check(cd,
		requireSubject(),
		requireAlias(),
		requireParentAlias(),
		validAtLeastYears(1)); err != nil {
		return err
	}
	cd.SelfSigned = false
	cd.IsCA = true
	return cm.create(cd)
}

func (cm *certMgr) NewLeaf(cd *CertData) error {
	if err := check(cd, requireSubject(),
		requireAlias(),
		requireParentAlias(),
		validAtLeastYears(1)); err != nil {
		return err
	}
	cd.SelfSigned = false
	cd.IsCA = false
	return cm.create(cd)
}

func getKeyUsage(cd *CertData) x509.KeyUsage {
	if cd.IsCA {
		return x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		return x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature
	}
}

// create creates new certificate based on input data.
func (cm *certMgr) create(cd *CertData) error {
	var (
		err error
		ch  *PairHolder
	)
	newCert := &x509.Certificate{
		Subject:               cd.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(cd.ValidYears, 0, 0),
		IsCA:                  cd.IsCA,
		KeyUsage:              getKeyUsage(cd),
		BasicConstraintsValid: true,
	}

	if !cd.SelfSigned {
		ch, err = cm.load(cd.ParentAlias)
		if err != nil {
			return err
		}
		newCert.Issuer = ch.Cert.Subject
	} else {
		newCert.Issuer = cd.Issuer
	}

	if cd.Serial != 0 {
		newCert.SerialNumber = big.NewInt(cd.Serial)
	} else {
		newCert.SerialNumber = big.NewInt(0)
	}

	if !cd.IsCA {
		newCert.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		}
		newCert.DNSNames = cd.DNSSan
		newCert.IPAddresses = cd.IPSan
	}

	newKey, err := rsa.GenerateKey(rand.Reader, cd.KeySize)
	if err != nil {
		return err
	}

	var (
		parentCert *x509.Certificate
		privateKey *rsa.PrivateKey
	)

	if cd.SelfSigned {
		parentCert = newCert
		privateKey = newKey
	} else {
		privateKey = ch.Key
		parentCert = ch.Cert
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, newCert, parentCert, &newKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	return cm.save(certBytes, x509.MarshalPKCS1PrivateKey(newKey), cd.Alias)
}

func (cm *certMgr) save(cert []byte, key []byte, alias string) error {
	certPem := new(bytes.Buffer)
	err := pem.Encode(certPem, &pem.Block{
		Type:  typeCert,
		Bytes: cert,
	})
	if err != nil {
		return err
	}

	keyPem := new(bytes.Buffer)
	err = pem.Encode(keyPem, &pem.Block{
		Type:  typeRsaPrivateKey,
		Bytes: key,
	})
	if err != nil {
		return err
	}
	err = os.WriteFile(cm.aliasToFile(alias, false), certPem.Bytes(), 0o640)
	if err != nil {
		return err
	}
	return os.WriteFile(cm.aliasToFile(alias, true), keyPem.Bytes(), 0o400)
}

// load loads both certificate and private key for given alias
func (cm *certMgr) load(alias string) (*PairHolder, error) {
	name := fmt.Sprintf("%s/%s.pem", cm.dir, alias)
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != typeCert {
		return nil, fmt.Errorf("can't load CA certificate from %s", name)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	name = fmt.Sprintf("%s/%s.key", cm.dir, alias)
	data, err = os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(data)
	if block == nil || block.Type != typeRsaPrivateKey {
		return nil, fmt.Errorf("can't load CA private key from %s", name)
	}
	pKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &PairHolder{
		Cert: cert,
		Key:  pKey,
	}, nil
}

func New(dir string) Interface {
	return &certMgr{
		dir: dir,
	}
}
