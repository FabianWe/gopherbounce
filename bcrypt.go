// Copyright 2018 Fabian Wenzelmann
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gopherbounce

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptConf contains all parameters for bcrypt.
type BcryptConf struct {
	Cost int
}

// Copy returns a copy of a config.
func (conf *BcryptConf) Copy() *BcryptConf {
	return &BcryptConf{Cost: conf.Cost}
}

// String returns a human-readable string representation.
func (conf *BcryptConf) String() string {
	return fmt.Sprintf("&{Cost: %d}", conf.Cost)
}

// DefaultBcryptConf is the default configuration for bcrypt.
var DefaultBcryptConf = &BcryptConf{Cost: 12}

// BcryptHasher is a Hasher using bcrypt.
type BcryptHasher struct {
	*BcryptConf
}

// NewBcryptHasher returns a new BcryptHasher with the given parameters.
func NewBcryptHasher(conf *BcryptConf) *BcryptHasher {
	if conf == nil {
		conf = DefaultBcryptConf.Copy()
	}
	return &BcryptHasher{conf}
}

// Copy returns a copy of the hasher.
func (h *BcryptHasher) Copy() BcryptHasher {
	return BcryptHasher{h.BcryptConf.Copy()}
}

// Generate implements the Hasher interface. All errors returned are from
// golang.org/x/crypto/bcrypt.
func (h *BcryptHasher) Generate(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), h.Cost)
}

// ParseBcryptConf parses a configuration from a hashed version.
func ParseBcryptConf(hashed []byte) (*BcryptConf, error) {
	cost, costErr := bcrypt.Cost(hashed)
	if costErr != nil {
		return nil, costErr
	}
	return &BcryptConf{Cost: cost}, nil
}

// BcryptValidator implements Validator for bcrypt hashes.
type BcryptValidator struct{}

// Compare implements the Validator interface for bcrypt hashes.
func (v BcryptValidator) Compare(hashed []byte, password string) error {
	// catch missmatch error from bcrypt library
	err := bcrypt.CompareHashAndPassword(hashed, []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return NewPasswordMismatchError()
	}
	return err
}
