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
	"crypto/rand"
	"crypto/subtle"
	"io"
	"strings"
)

func GenSalt(numBytes int) ([]byte, error) {
	salt := make([]byte, numBytes)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

type Hasher interface {
	Generate(password string) ([]byte, error)
}

type HashGenerator interface {
	Key(password string, salt []byte) ([]byte, error)
}

type Validator interface {
	Compare(hashed []byte, password string) error
}

func CompareHashes(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

var (
	Bcrypt        = NewBcryptHasher(nil)
	Scrypt        = NewScryptHasher(nil)
	Argon2i       = NewArgon2iHasher(nil)
	Argon2id      = NewArgon2idHasher(nil)
	DefaultHasher = NewArgon2idHasher(nil)
)

var (
	BcryptVal = BcryptValidator{}
	ScryptVal = ScryptValidator{}
	Argon2iVal = Argon2iValidator{}
	Argon2idVal = Argon2idValidator{}
)

//go:generate stringer -type=HashAlg

type HashAlg int

const (
	BcryptAlg HashAlg = iota
	ScryptAlg
	Argon2iAlg
	Argon2idAlg
)

func GuessAlg(hashed []byte) HashAlg {
	s := string(hashed)
	switch {
	case strings.HasPrefix(s, "$2a$"):
		return BcryptAlg
	case strings.HasPrefix(s, "$4s$"):
		return ScryptAlg
	case strings.HasPrefix(s, "$argon2i$"):
		return Argon2iAlg
	case strings.HasPrefix(s, "$argon2id$"):
		return Argon2idAlg
	default:
		return HashAlg(-1)
	}
}

func GuessValidator(hashed []byte) Validator {
	switch GuessAlg(hashed) {
	case BcryptAlg:
		return BcryptVal
	case ScryptAlg:
		return ScryptVal
	case Argon2iAlg:
		return Argon2iVal
	case Argon2idAlg:
		return Argon2idVal
	default:
		return nil
	}
}

type ValidatorFunc func(password string) error

func GuessValidatorFunc(hashed []byte) ValidatorFunc {
	val := GuessValidator(hashed)
	return func(password string) error {
		if val == nil {
			return NewUnknownAlgError()
		}
		return val.Compare(hashed, password)
	}
}
