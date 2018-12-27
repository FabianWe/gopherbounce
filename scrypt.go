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

type ScryptConf struct {
	N, R, P, KeyLen int
}

func (conf *ScryptConf) Copy() *ScryptConf {
	return &ScryptConf{
		N:      conf.N,
		R:      conf.R,
		P:      conf.P,
		KeyLen: conf.KeyLen,
	}
}

var DefaultScryptConf = &ScryptConf{N: 32768, R: 8, P: 1, KeyLen: 32}

type ScryptData struct {
	// encoded with base64
	Salt, Key       string
	RawSalt, RawKey []byte
}

type ScryptHasher struct {
	*ScryptConf
}

func NewScryptHasher(conf *ScryptConf) *ScryptHasher {
	if conf == nil {
		conf = DefaultScryptConf
	}
	return &ScryptHasher{conf}
}

func (h *ScryptHasher) Key(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, h.N, h.R, h.P, h.KeyLen)
}

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

func (c scryptComponents) rawSalt() ([]byte, error) {
	fmt.Println("DECODE SALT", c.getSalt())
	dec, decErr := Base64Decode([]byte(c.getSalt()))
	if decErr != nil {
		return nil, NewSyntaxError("gopherbounce/scrypt: Invalid format string: Invalid base64 " + decErr.Error())
	}
	return dec, nil
}

func (c scryptComponents) parseInt(s string) (int, error) {
	asInt, err := strconv.Atoi(s)
	if err != nil {
		return -1, NewSyntaxError("gopherbounce/scrypt: Invalid format string: Invalid integer " + err.Error())
	}
	return asInt, nil
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

func (c scryptComponents) keyLen() int {
	// base64 key len is not correct, it returns the max length, not the actual
	// length
	key := c.getKey()
	return DefaultEncoding.Encoding.DecodedLen(len(key))
}

func (c scryptComponents) rawKey() ([]byte, error) {
	fmt.Println("DECODE KEY", c.getKey())
	dec, decErr := Base64Decode([]byte(c.getKey()))
	if decErr != nil {
		return nil, NewSyntaxError("gopherbounce/scrypt: Invalid format string: Invalid base64 " + decErr.Error())
	}
	return dec, nil
}

func (c scryptComponents) getConfig() (*ScryptConf, error) {
	var n, r, p, keyLen int
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
	keyLen = c.keyLen()
	res := &ScryptConf{
		N:      n,
		R:      r,
		P:      p,
		KeyLen: keyLen,
	}
	return res, nil
}

func (c scryptComponents) getData() (*ScryptData, error) {
	salt, key := c.getSalt(), c.getKey()
	rawSalt, saltErr := c.rawSalt()
	if saltErr != nil {
		return nil, saltErr
	}
	rawKey, keyErr := c.rawKey()
	if keyErr != nil {
		return nil, keyErr
	}
	result := ScryptData{
		Salt:    salt,
		Key:     key,
		RawSalt: rawSalt,
		RawKey:  rawKey,
	}
	return &result, nil
}

func ParseScryptConf(hashed []byte) (*ScryptConf, error) {
	s := string(hashed)
	split, splitErr := parseScryptComponents(s)
	if splitErr != nil {
		return nil, splitErr
	}
	return split.getConfig()
}

func ParseScryptData(hashed []byte) (*ScryptData, error) {
	s := string(hashed)
	split, splitErr := parseScryptComponents(s)
	if splitErr != nil {
		return nil, splitErr
	}
	return split.getData()
}

func ParseScrypt(hashed []byte) (*ScryptConf, *ScryptData, error) {
	s := string(hashed)
	split, splitErr := parseScryptComponents(s)
	if splitErr != nil {
		return nil, nil, splitErr
	}
	conf, confErr := split.getConfig()
	if confErr != nil {
		return nil, nil, confErr
	}
	data, dataErr := split.getData()
	if dataErr != nil {
		return nil, nil, dataErr
	}
	return conf, data, nil
}
