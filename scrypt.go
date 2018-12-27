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
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// ScryptConf contains all parameters for scrypt.
type ScryptConf struct {
	N, R, P, KeyLen int
}

// Copy returns a copy of a config.
func (conf *ScryptConf) Copy() *ScryptConf {
	return &ScryptConf{
		N:      conf.N,
		R:      conf.R,
		P:      conf.P,
		KeyLen: conf.KeyLen,
	}
}

// String returns a human-readable string reprensetation.
func (conf *ScryptConf) String() string {
	return fmt.Sprintf("&{N: %d, R: %d, P: %d, KeyLen: %d}", conf.N, conf.R, conf.P, conf.KeyLen)
}

// DefaultScryptConf is the default configuration for scrypt.
var DefaultScryptConf = &ScryptConf{N: 131072, R: 8, P: 1, KeyLen: 32}

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
	return scrypt.Key([]byte(password), salt, h.N, h.R, h.P, h.KeyLen)
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
	result := fmt.Sprintf("$4s$%s$%d$%d$%d$%s", saltEnc, h.N, h.R, h.P, keyEnc)
	return []byte(result), nil
}

// scryptComponents is used for parsing a scrypt hash string. The entries are
// splitted by the separator ($).
type scryptComponents []string

func parseScryptComponents(s string) (scryptComponents, error) {
	split := strings.Split(s, "$")
	if len(split) != 7 {
		return nil, NewSyntaxError("gopherbounce/scrypt: Invalid format string (invalid number of separators)")
	}
	return scryptComponents(split), nil
}

func (c scryptComponents) getVersion() string {
	return c[1]
}

func (c scryptComponents) getSalt() string {
	return c[2]
}

func (c scryptComponents) parseInt(s string) (int, error) {
	asInt, err := strconv.Atoi(s)
	if err != nil {
		return -1, NewSyntaxError("gopherbounce/scrypt: Invalid format string: Invalid integer " + err.Error())
	}
	return asInt, nil
}

func (c scryptComponents) decode(s string) ([]byte, error) {
	dec, decErr := Base64Decode([]byte(s))
	if decErr != nil {
		return nil, NewSyntaxError("gopherbounce/scrypt: Invalid format string: Invalid base64 " + decErr.Error())
	}
	return dec, nil
}

func (c scryptComponents) getN() (int, error) {
	return c.parseInt(c[3])
}

func (c scryptComponents) getR() (int, error) {
	return c.parseInt(c[4])
}

func (c scryptComponents) getP() (int, error) {
	return c.parseInt(c[5])
}

func (c scryptComponents) getKey() string {
	return c[6]
}

func (c scryptComponents) rawSalt() ([]byte, error) {
	return c.decode(c.getSalt())
}

func (c scryptComponents) rawKey() ([]byte, error) {
	return c.decode(c.getKey())
}

func (c scryptComponents) getConfig() (*ScryptConf, error) {
	var n, r, p int
	var err error
	n, err = c.getN()
	if err != nil {
		return nil, err
	}
	r, err = c.getR()
	if err != nil {
		return nil, err
	}
	p, err = c.getP()
	if err != nil {
		return nil, err
	}
	res := &ScryptConf{
		N: n,
		R: r,
		P: p,
		// KeyLen not computed here, is computed from the actual data
		KeyLen: -1,
	}
	return res, nil
}

func (c scryptComponents) getData() (*ScryptData, error) {
	config, configErr := c.getConfig()
	if configErr != nil {
		return nil, configErr
	}
	salt, key := c.getSalt(), c.getKey()
	rawSalt, saltErr := c.rawSalt()
	if saltErr != nil {
		return nil, saltErr
	}
	rawKey, keyErr := c.rawKey()
	if keyErr != nil {
		return nil, keyErr
	}
	config.KeyLen = len(rawKey)
	result := ScryptData{
		ScryptConf: config,
		Salt:       salt,
		Key:        key,
		RawSalt:    rawSalt,
		RawKey:     rawKey,
	}
	return &result, nil
}

// ParseScryptData parses scrypt data from the hashed version.
func ParseScryptData(hashed []byte) (*ScryptData, error) {
	s := string(hashed)
	split, splitErr := parseScryptComponents(s)
	if splitErr != nil {
		return nil, splitErr
	}
	if split.getVersion() != "4s" {
		return nil, NewVersionError("gopherbounce/scrypt", "4s", split.getVersion())
	}
	data, dataErr := split.getData()
	if dataErr != nil {
		return nil, dataErr
	}
	return data, nil
}

// ScryptValidator implements Validator for scrypt hashes.
type ScryptValidator struct {}

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
