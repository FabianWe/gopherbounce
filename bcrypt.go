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

import "golang.org/x/crypto/bcrypt"

type BcryptConf struct {
	Cost int
}

func (conf *BcryptConf) Copy() *BcryptConf {
	return &BcryptConf{Cost: conf.Cost}
}

var DefaultBcryptConf = &BcryptConf{bcrypt.DefaultCost}

type BcryptHasher struct {
	*BcryptConf
}

func NewBcryptHasher(conf *BcryptConf) BcryptHasher {
	if conf == nil {
		conf = DefaultBcryptConf.Copy()
	}
	return BcryptHasher{conf}
}

func (h BcryptHasher) Copy() BcryptHasher {
	return BcryptHasher{h.BcryptConf.Copy()}
}

func (h BcryptHasher) Generate(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), h.Cost)
}

func ParseBcryptConf(hashed []byte) (*BcryptConf, error) {
	cost, costErr := bcrypt.Cost(hashed)
	if costErr != nil {
		return nil, costErr
	}
	return &BcryptConf{Cost: cost}, nil
}

func (h BcryptHasher) Compare(hashed []byte, password string) error {
	// catch missmatch error from bcrypt library
	err := bcrypt.CompareHashAndPassword(hashed, []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return NewPasswordMismatchError()
	}
	return err
}
