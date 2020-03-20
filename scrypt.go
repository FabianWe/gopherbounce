// Copyright 2018 - 2020 Fabian Wenzelmann
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
	"log"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

// ScryptConf contains all parameters for scrypt.
type ScryptConf struct {
	n, rounds, R, P, KeyLen int
}

func NewScryptConf(rounds, r, p, keyLen int) *ScryptConf {
	res := &ScryptConf{
		R:      r,
		P:      p,
		KeyLen: keyLen,
	}
	res.SetRounds(rounds)
	return res
}

// Copy returns a copy of a config.
func (conf *ScryptConf) Copy() *ScryptConf {
	return &ScryptConf{
		rounds: conf.rounds,
		n:      conf.n,
		R:      conf.R,
		P:      conf.P,
		KeyLen: conf.KeyLen,
	}
}

// String returns a human-readable string reprensetation.
func (conf *ScryptConf) String() string {
	return fmt.Sprintf("&{rounds: %d, R: %d, P: %d, KeyLen: %d}", conf.rounds, conf.R, conf.P, conf.KeyLen)
}

func (conf *ScryptConf) GetN() int {
	return conf.n
}

func (conf *ScryptConf) GetRounds() int {
	return conf.rounds
}

func (conf *ScryptConf) SetRounds(rounds int) {
	pow := Pow(2, int64(rounds))
	asInt := int(pow)
	if asInt <= 0 {
		log.Printf("Invalid rounds parameter for scrypt: %d. Using default (17)\n", rounds)
		asInt = 65536
		rounds = 16
	}
	conf.rounds = rounds
	conf.n = asInt
}

// DefaultScryptConf is the default configuration for scrypt.
var DefaultScryptConf = NewScryptConf(16, 8, 1, 64)

// ScryptData stores in addition to a config also the salt and key, both
// base64 encoded (Salt and Key) as well as the raw version (decoded from
// Salt and Key).
type ScryptData struct {
	*ScryptConf
	// encoded with base64
	Salt, Key       string
	RawSalt, RawKey []byte
}

// ScryptHasher is a Hasher using scrypt.
type ScryptHasher struct {
	*ScryptConf
}

// NewScryptHasher returns a new ScryptHasher with the given parameters.
func NewScryptHasher(conf *ScryptConf) *ScryptHasher {
	if conf == nil {
		conf = DefaultScryptConf
	}
	return &ScryptHasher{conf}
}

// Copy returns a copy of the hasher.
func (h *ScryptHasher) Copy() *ScryptHasher {
	return &ScryptHasher{h.ScryptConf.Copy()}
}

// Key returns the scrypt key of the password given the clear text password,
// salt and parameters from the config of the Hasher.
func (h *ScryptHasher) Key(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, h.n, h.R, h.P, h.KeyLen)
}

// Generate implements the Hasher interface.
func (h *ScryptHasher) Generate(password string) ([]byte, error) {
	salt, saltErr := GenSalt(h.KeyLen)
	if saltErr != nil {
		return nil, saltErr
	}
	key, err := h.Key(password, salt)
	if err != nil {
		return nil, err
	}
	// encode salt and key with base64
	saltEnc, keyEnc := Base64Encode(salt), Base64Encode(key)
	phc := PHC{
		ID:     "scrypt",
		Params: []string{strconv.Itoa(h.GetRounds()), strconv.Itoa(h.R), strconv.Itoa(h.P)},
		Salt:   string(saltEnc),
		Hash:   string(keyEnc),
	}
	res, err := phc.EncodeString(PHCScryptConfig)
	if err != nil {
		return nil, err
	}
	return []byte(res), nil
}

// ParseScryptData parses scrypt data from the hashed version.
func ParseScryptData(hashed []byte) (*ScryptData, error) {
	s := string(hashed)
	parsed, err := ParsePHC(s, PHCScryptConfig)
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	if parsed.ID != ScryptName {
		return nil, NewSyntaxError(fmt.Sprintf("Can't parse scrypt, algorithm id is %s", parsed.ID))
	}
	salt, key := parsed.Salt, parsed.Hash
	if len(salt) == 0 || len(key) == 0 {
		return nil, NewSyntaxError("scrypt requires salt and hash in encoded string")
	}
	rawSalt, err := Base64Decode([]byte(salt))
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	rawKey, err := Base64Decode([]byte(key))
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	if len(parsed.Params) != 3 {
		return nil, fmt.Errorf("gopherbounce/scrypt: Internal error: phc parser for scrypt returned wrong number of parameters (got %d, expected %d)",
			len(parsed.Params), 3)
	}
	rounds, err := strconv.Atoi(parsed.Params[0])
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	r, err := strconv.Atoi(parsed.Params[1])
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	p, err := strconv.Atoi(parsed.Params[2])
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	config := NewScryptConf(rounds, r, p, len(rawKey))
	data := ScryptData{
		ScryptConf: config,
		Salt:       salt,
		Key:        key,
		RawSalt:    rawSalt,
		RawKey:     rawKey,
	}
	return &data, nil
}

// ScryptValidator implements Validator for scrypt hashes.
type ScryptValidator struct{}

// Compare implements the Validator interface for scrypt hashes.
func (v ScryptValidator) Compare(hashed []byte, password string) error {
	// parse configuration from stored entry
	data, dataErr := ParseScryptData(hashed)
	if dataErr != nil {
		return dataErr
	}
	// create a hasher with the computed config
	hasher := NewScryptHasher(data.ScryptConf)
	// compute key
	key, keyErr := hasher.Key(password, data.RawSalt)
	if keyErr != nil {
		return keyErr
	}
	if CompareHashes(key, data.RawKey) {
		return nil
	}
	return NewPasswordMismatchError()
}
