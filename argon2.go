// Copyright 2018, 2019 Fabian Wenzelmann
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
	"math"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Conf contains all parameters for argon2, it is used by argon2i and
// argon2id.
type Argon2Conf struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

// Copy returns a copy of a config.
func (conf *Argon2Conf) Copy() *Argon2Conf {
	return &Argon2Conf{
		Time:    conf.Time,
		Memory:  conf.Memory,
		Threads: conf.Threads,
		KeyLen:  conf.KeyLen,
	}
}

// String returns a human-readable string reprensetation.
func (conf *Argon2Conf) String() string {
	return fmt.Sprintf("&{Time: %d, Memory: %d, Threads: %d, KeyLen: %d}",
		conf.Time, conf.Memory, conf.Threads, conf.KeyLen)
}

// Argon2iConf contains all parameters for argon2i.
type Argon2iConf struct {
	*Argon2Conf
}

// Argon2iData stores in addition to a config also the salt and key, both
// base64 encoded (Salt and Key) as well as the raw version (decoded from
// Salt and Key).
type Argon2iData struct {
	*Argon2iConf
	Salt, Key       string
	RawSalt, RawKey []byte
}

// Copy returns a copy of a config.
func (conf *Argon2iConf) Copy() *Argon2iConf {
	return &Argon2iConf{conf.Argon2Conf.Copy()}
}

// Argon2iHasher is a Hasher using argon2i.
type Argon2iHasher struct {
	*Argon2iConf
}

// NewArgon2iHasher returns a new NewArgon2iHasher with the given parameter.
func NewArgon2iHasher(conf *Argon2iConf) *Argon2iHasher {
	if conf == nil {
		numCPUs := runtime.NumCPU()
		// just to be  absolutely sure we have some sensible value
		if numCPUs <= 0 || numCPUs >= math.MaxUint8 {
			numCPUs = 4
		}
		asUint := uint8(numCPUs)
		conf = &Argon2iConf{
			Argon2Conf: &Argon2Conf{Time: 10, Memory: 64 * 1024, Threads: asUint, KeyLen: 32},
		}
	}
	return &Argon2iHasher{conf}
}

// Copy returns a copy of the hasher.
func (h *Argon2iHasher) Copy() *Argon2iHasher {
	return &Argon2iHasher{h.Argon2iConf.Copy()}
}

// Key returns the argon2i key of the password given the clear text password,
// salt and parameters from the config of the Hasher.
func (h *Argon2iHasher) Key(password string, salt []byte) ([]byte, error) {
	key := argon2.Key([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	return key, nil
}

// Generate implements the Hasher interface.
func (h *Argon2iHasher) Generate(password string) ([]byte, error) {
	salt, saltErr := GenSalt(int(h.KeyLen))
	if saltErr != nil {
		return nil, saltErr
	}
	key, keyErr := h.Key(password, salt)
	if keyErr != nil {
		return nil, keyErr
	}
	// encode salt and key
	saltEnc, keyEnc := Base64Encode(salt), Base64Encode(key)
	// result := fmt.Sprintf("$argon2i$%d$%d$%d$%d$%s$%s", argon2.Version, h.Memory, h.Time, h.Threads, saltEnc, keyEnc)
	// return []byte(result), nil

	// pch
	phc := &PHC{
		ID:   "argon2i",
		Salt: string(saltEnc),
		Hash: string(keyEnc),
		Params: []string{
			fmt.Sprintf("%d", h.Memory),
			fmt.Sprintf("%d", h.Time),
			fmt.Sprintf("%d", h.Threads),
			fmt.Sprintf("%d", argon2.Version),
		},
	}

	res, err := phc.Encode(PHCArgon2Config)
	if err != nil {
		return nil, err
	}
	return []byte(res), nil
}

// Argon2idConf contains all parameters for argon2id.
type Argon2idConf struct {
	*Argon2Conf
}

// Argon2idData stores in addition to a config also the salt and key, both
// base64 encoded (Salt and Key) as well as the raw version (decoded from
// Salt and Key).
type Argon2idData struct {
	*Argon2idConf
	// encoded with base64
	Salt, Key       string
	RawSalt, RawKey []byte
}

// Copy returns a copy of a config.
func (conf *Argon2idConf) Copy() *Argon2idConf {
	return &Argon2idConf{conf.Argon2Conf.Copy()}
}

// Argon2idHasher is a Hasher using argon2id.
type Argon2idHasher struct {
	*Argon2idConf
}

// NewArgon2idHasher returns a new NewArgon2idHasher with the given parameter.
func NewArgon2idHasher(conf *Argon2idConf) *Argon2idHasher {
	if conf == nil {
		numCPUs := runtime.NumCPU()
		// just to be  absolutely sure we have some sensible value
		if numCPUs <= 0 || numCPUs >= math.MaxUint8 {
			numCPUs = 4
		}
		asUint := uint8(numCPUs)
		conf = &Argon2idConf{
			Argon2Conf: &Argon2Conf{Time: 3, Memory: 64 * 1024, Threads: asUint, KeyLen: 32},
		}
	}
	return &Argon2idHasher{conf}
}

// Copy returns a copy of the hasher.
func (h *Argon2idHasher) Copy() *Argon2idHasher {
	return &Argon2idHasher{h.Argon2idConf.Copy()}
}

// Key returns the argon2id key of the password given the clear text password,
// salt and parameters from the config of the Hasher.
func (h *Argon2idHasher) Key(password string, salt []byte) ([]byte, error) {
	key := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	return key, nil
}

// Generate implements the Hasher interface.
func (h *Argon2idHasher) Generate(password string) ([]byte, error) {
	salt, saltErr := GenSalt(int(h.KeyLen))
	if saltErr != nil {
		return nil, saltErr
	}
	key, keyErr := h.Key(password, salt)
	if keyErr != nil {
		return nil, keyErr
	}
	saltEnc, keyEnc := Base64Encode(salt), Base64Encode(key)
	// result := fmt.Sprintf("$argon2id$%d$%d$%d$%d$%s$%s", argon2.Version, h.Memory, h.Time, h.Threads, saltEnc, keyEnc)
	// return []byte(result), nil

	// pch
	phc := &PHC{
		ID:   "argon2id",
		Salt: string(saltEnc),
		Hash: string(keyEnc),
		Params: []string{
			fmt.Sprintf("%d", h.Memory),
			fmt.Sprintf("%d", h.Time),
			fmt.Sprintf("%d", h.Threads),
			fmt.Sprintf("%d", argon2.Version),
		},
	}

	res, err := phc.Encode(PHCArgon2Config)
	if err != nil {
		return nil, err
	}
	return []byte(res), nil
}

func ParseArgon2Conf(hashed []byte) (*PHC, *Argon2Conf, error) {
	s := string(hashed)
	parsed, err := ParsePHC(s, PHCArgon2Config)
	if err != nil {
		return parsed, nil, NewSyntaxError(err.Error())
	}
	if !strings.HasPrefix(parsed.ID, "argon2") {
		return parsed, nil, NewSyntaxError(fmt.Sprintf("Invalid algorithm %s: Does not start with argon2", parsed.ID))
	}
	if len(parsed.Params) != 4 {
		return parsed,
			nil,
			fmt.Errorf("gopherbounce/argon2: Internal error: phc parser for argon2 returned wrong number of parameters (got %d, expected %d)",
				len(parsed.Params), 4)
	}
	m64, err := strconv.ParseUint(parsed.Params[0], 10, 32)
	if err != nil {
		return parsed, nil, NewSyntaxError(err.Error())
	}
	m := uint32(m64)
	t64, err := strconv.ParseUint(parsed.Params[1], 10, 32)
	if err != nil {
		return parsed, nil, NewSyntaxError(err.Error())
	}
	t := uint32(t64)
	p64, err := strconv.ParseUint(parsed.Params[2], 10, 8)
	if err != nil {
		return parsed, nil, NewSyntaxError(err.Error())
	}
	p := uint8(p64)
	result := Argon2Conf{
		Time:    t,
		Memory:  m,
		Threads: p,
		// not computed here
		KeyLen: 0,
	}
	return parsed, &result, nil
}

// ParseArgon2iData parses argon2i data from the hashed version.
func ParseArgon2iData(hashed []byte) (*Argon2iData, error) {
	parsed, conf, err := ParseArgon2Conf(hashed)
	if err != nil {
		return nil, err
	}
	if parsed.ID != "argon2i" {
		return nil, NewSyntaxError(fmt.Sprintf("Invalid algorithm %s: Must be \"argon2i\"", parsed.ID))
	}
	salt, key := parsed.Salt, parsed.Hash
	if len(salt) == 0 || len(key) == 0 {
		return nil, NewSyntaxError("argon2i requires salt and hash in encoded string")
	}
	rawSalt, err := Base64Decode([]byte(salt))
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	rawKey, err := Base64Decode([]byte(key))
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	conf.KeyLen = uint32(len(rawKey))
	innerConf := &Argon2iConf{conf}
	result := Argon2iData{
		Argon2iConf: innerConf,
		Salt:        salt,
		Key:         key,
		RawSalt:     rawSalt,
		RawKey:      rawKey,
	}
	return &result, nil
}

// ParseArgon2idData parses argon2id data from the hashed version.
func ParseArgon2idData(hashed []byte) (*Argon2idData, error) {
	parsed, conf, err := ParseArgon2Conf(hashed)
	if err != nil {
		return nil, err
	}
	if parsed.ID != "argon2id" {
		return nil, NewSyntaxError(fmt.Sprintf("Invalid algorithm %s: Must be \"argon2id\"", parsed.ID))
	}
	salt, key := parsed.Salt, parsed.Hash
	if len(salt) == 0 || len(key) == 0 {
		return nil, NewSyntaxError("argon2id requires salt and hash in encoded string")
	}
	rawSalt, err := Base64Decode([]byte(salt))
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	rawKey, err := Base64Decode([]byte(key))
	if err != nil {
		return nil, NewSyntaxError(err.Error())
	}
	conf.KeyLen = uint32(len(rawKey))
	innerConf := &Argon2idConf{conf}
	result := Argon2idData{
		Argon2idConf: innerConf,
		Salt:         salt,
		Key:          key,
		RawSalt:      rawSalt,
		RawKey:       rawKey,
	}
	return &result, nil
}

// Argon2iValidator implements Validator for argon2i hashes.
type Argon2iValidator struct{}

// Compare implements the Validator interface for argon2i hashes.
func (v Argon2iValidator) Compare(hashed []byte, password string) error {
	// parse configuration from stored entry
	data, dataErr := ParseArgon2iData(hashed)
	if dataErr != nil {
		return dataErr
	}
	// create a hasher with the computed config
	hasher := NewArgon2iHasher(data.Argon2iConf)
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

// Argon2idValidator implements Validator for argon2id hashes.
type Argon2idValidator struct{}

// Compare implements the Validator interface for argon2id hashes.
func (v Argon2idValidator) Compare(hashed []byte, password string) error {
	// parse configuration from stored entry
	data, dataErr := ParseArgon2idData(hashed)
	if dataErr != nil {
		return dataErr
	}
	// create a hasher with the computed config
	hasher := NewArgon2idHasher(data.Argon2idConf)
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
