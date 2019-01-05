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
	"fmt"
	"io"
	"strings"
)

const (
	// BcryptName is the name of the bcrypt algorithm.
	BcryptName = "bcrypt"

	// ScryptName is the name of the scrypt algorithm.
	ScryptName = "scrypt"

	// Argon2iName is the name of the Argon2i algorithm.
	Argon2iName = "argon2i"

	// Argon2idName is the name of the Argon2id algorithm.
	Argon2idName = "argon2id"

	// BcryptPrefix is the algorithm prefix in the hash encoding.
	BcryptPrefix = "$2a$"

	// ScryptPrefix is the algorithm prefix in the hash encoding.
	ScryptPrefix = "$4s$"

	// Argon2iPrefix is the algorithm prefix in the hash encoding.
	Argon2iPrefix = "$argon2i$"

	// Argon2idPrefix is the algorithm prefix in the hash encoding.
	Argon2idPrefix = "$argon2id$"
)

// GenSalt computes a cryptographically secure salt given the number of bytes.
func GenSalt(numBytes int) ([]byte, error) {
	salt := make([]byte, numBytes)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

// Hasher is the general interface for creating hashed versions of passwords.
// The returned encoded string contains all information required for parsing
// the parameters of the key function
// (like https://openwall.info/wiki/john/sample-hashes).
type Hasher interface {
	Generate(password string) ([]byte, error)
}

// HashGenerator is an interface describing all algorithms that can be used
// to directly create a hashed version of a password. The difference between
// HashGenerator and Hasher is that Hasher returns a formatted string whereas
// HashGenerator returns the raw generated key.
type HashGenerator interface {
	Key(password string, salt []byte) ([]byte, error)
}

// Validator is an interface that provides a method to compare a hashed version
// of a password with a prorivde clear text version. Any error returned should
// be considered as an authentication fail. Only a nil return value.indicates
// success.
//
// There are some predefined errors that can help you to narrow the cause.
// But not all implementaions are required to use these errors.
// Special errors include: Syntax error if the hases version can't be parsed.
// VersionError: IF the version used to created the hashes value is not
// compatible with the implemented algorithm.
// AlgIDError: The provided algorithm prefix does not match the prefix required
// by the validator.
// PasswordMismatchError: If the clear text version is not the password used to
// create the hash.
//
// Note that a valdiator implementation provides validation for a specific
// hashing algorithm, like one implementation for bcrypt, scrypt etc.
// If you want to validate a hashed version without knowing the used algorithm
// use GuessValidator or GuessValidatorFunc.
type Validator interface {
	Compare(hashed []byte, password string) error
}

// CompareHashes uses a constant time compare algorithm to compare to key
// hashes. Constant time compare functions are important or otherwise attackers
// might infer knowledge about the real password.
func CompareHashes(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

var (
	// Bcrypt is a bcrypt Hasher.
	Bcrypt = NewBcryptHasher(nil)

	// Scrypt is a scrypt Hasher.
	Scrypt = NewScryptHasher(nil)

	// Argon2i is a argon2 Hasher using the Argon2i key function.
	Argon2i = NewArgon2iHasher(nil)

	// Argon2id is a argon2 Hasher using the Argon2id key function.
	// Argon2id is considered more secure than Argon2i.
	Argon2id = NewArgon2idHasher(nil)

	// DefaultHasher ia a rather secure Hasher that should be safe to be used
	// by most applications. At the moment it's  Argon2id with the default
	// paramters.
	DefaultHasher = NewArgon2idHasher(nil)
)

var (
	// BcryptVal is a Validator for bcrypt encoded hashes.
	BcryptVal = BcryptValidator{}

	// ScryptVal is a Validator for scrypt encoded hashes.
	ScryptVal = ScryptValidator{}

	// Argon2iVal is a Validator for argon2i encoded hashes.
	Argon2iVal = Argon2iValidator{}

	// Argon2idVal is a Validator for argon2id encoded hashes.
	Argon2idVal = Argon2idValidator{}
)

//go:generate stringer -type=HashAlg

// HashAlg is a type used to enumerate all implemented algorithms.
type HashAlg int

const (
	// BcryptAlg stands for the bcrypt algorithm.
	BcryptAlg HashAlg = iota

	// ScryptAlg stands for the scrypt algorithm.
	ScryptAlg

	// Argon2iAlg stands for the argon2i algorithm.
	Argon2iAlg

	// Argon2idAlg stands for the argon2id algorithm.
	Argon2idAlg
)

// ParseAlg parses the algorithm from the algorith name.
// Valid names are "bcrypt", "scrypt", "argon2i" and "argon2id".
func ParseAlg(name string) (HashAlg, error) {
	switch strings.ToLower(name) {
	case strings.ToLower(BcryptName):
		return BcryptAlg, nil
	case strings.ToLower(ScryptName):
		return ScryptAlg, nil
	case strings.ToLower(Argon2iName):
		return Argon2iAlg, nil
	case strings.ToLower(Argon2idName):
		return Argon2idAlg, nil
	default:
		return -1, fmt.Errorf("Invalid algorithm name: %s", name)
	}
}

// GuessAlg returns the algorithm used to create the specified hashed version.
// If the algorithm is unknown it returns -1.
func GuessAlg(hashed []byte) HashAlg {
	s := string(hashed)
	switch {
	case strings.HasPrefix(s, BcryptPrefix):
		return BcryptAlg
	case strings.HasPrefix(s, ScryptPrefix):
		return ScryptAlg
	case strings.HasPrefix(s, Argon2iPrefix):
		return Argon2iAlg
	case strings.HasPrefix(s, Argon2idPrefix):
		return Argon2idAlg
	default:
		return HashAlg(-1)
	}
}

// GuessValidator returns a validator for the hashes version.
// That is a clear text password can be compared with the hashed version using
// the validator.
// If the algorithm is unknown it returns nil.
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

// ValidatorFunc is a function that returns an error is specified in the
// Validator interface. GuessValidatorFunc can be used to create a ValidatorFunc
// from the hashed version of a password.
type ValidatorFunc func(password string) error

// GuessValidatorFunc guesses the algorithm based on the hashes version.
// The returned error is compatible with the Validator interface specification.
// In addition it might return an UnknownAlgError if the algorithm cannot be
// guessed from the hashed version.
func GuessValidatorFunc(hashed []byte) ValidatorFunc {
	val := GuessValidator(hashed)
	return func(password string) error {
		if val == nil {
			return NewUnknownAlgError()
		}
		return val.Compare(hashed, password)
	}
}

const (
	// MaxIntLength is the maximal length that we assume to an integer encoding
	// as a string can have.
	MaxIntLength = 20
)

// BcryptHashSize returns the hash size of bcrypt hashes.
func BcryptHashSize() int {
	return 60
}

// SycryptHashSize returns the maximal hash size of a scrypt hash with a key and
// salt of with KeyLen bytes. The length is the maximal length, not the actual
// length.
func SycryptHashSize(keyLen int) int {
	maxEncLength := DefaultEncoding.Encoding.EncodedLen(keyLen)
	return 4 + 4 + 3*MaxIntLength + 2*maxEncLength
}

// Argon2iHashSize returns the maximal hash size of a argon2i hash with a key
// and salt of with KeyLen bytes. The length is the maximal length, not the
// actual length.
func Argon2iHashSize(keyLen int) int {
	maxEncLength := DefaultEncoding.Encoding.EncodedLen(keyLen)
	return 9 + 5 + 4*MaxIntLength + 2*maxEncLength
}

// Argon2idHashSize returns the maximal hash size of a argon2id hash with a key
// and salt of with KeyLen bytes. The length is the maximal length, not the
// actual length.
func Argon2idHashSize(keyLen int) int {
	// +1 because of additional d in algorithm id
	return Argon2iHashSize(keyLen) + 1
}

// func ValidateAndRenew(validator Validator, hasher Hasher, cons Constraint, hashed []byte, password string) (auth error, newHash []byte, newHashErr error) {
// 	auth = validator.Compare(hashed, password)
// 	if auth != nil {
// 		return
// 	}
// 	// auth success, then check if
// 	return
// }
