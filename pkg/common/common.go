package common

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

func AddDirFlag(d *string, pf *pflag.FlagSet) {
	pf.StringVar(d, "directory", *d, "Directory to operate on")
}
