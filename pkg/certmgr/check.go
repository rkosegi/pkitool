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
	"fmt"
	"pkitool/pkg/common"
)

// function type to validate aspect of CertData
type checkFunc func(data *CertData) error

// requireAlias makes sure that alias is set
func requireAlias() checkFunc {
	return func(data *CertData) error {
		if len(data.Alias) == 0 {
			return common.ErrAliasMissing
		}
		return nil
	}
}

// requireAlias makes sure that alias is set
func requireSubject() checkFunc {
	return func(data *CertData) error {
		if len(data.Subject.String()) == 0 {
			return common.ErrSubjectMissing
		}
		return nil
	}
}

// requireParentAlias makes sure that parent alias is set
func requireParentAlias() checkFunc {
	return func(data *CertData) error {
		if len(data.ParentAlias) == 0 {
			return common.ErrParentAliasMissing
		}
		return nil
	}
}

func validAtLeastYears(years int) checkFunc {
	return func(data *CertData) error {
		if data.ValidYears < years {
			return fmt.Errorf("invalid ValidYears: %d, should be at least %d", data.ValidYears, years)
		}
		return nil
	}
}

func check(data *CertData, checks ...checkFunc) error {
	for _, checkFn := range checks {
		if err := checkFn(data); err != nil {
			return err
		}
	}
	return nil
}
