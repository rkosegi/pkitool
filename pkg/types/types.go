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

package types

import (
	"errors"

	"github.com/spf13/pflag"
)

var (
	ErrIssuerMissing      = errors.New("value for issuer is required")
	ErrAliasMissing       = errors.New("certificate alias is required")
	ErrSubjectMissing     = errors.New("certificate subject is required")
	ErrParentAliasMissing = errors.New("parent certificate alias is required")
)

const (
	BlockTypeCertificate = "CERTIFICATE"
)

func AddDirFlag(d *string, pf *pflag.FlagSet) {
	pf.StringVar(d, "directory", *d, "Directory to operate on")
}
