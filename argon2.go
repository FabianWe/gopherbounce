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
	"math"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Conf struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

func (conf *Argon2Conf) Copy() *Argon2Conf {
	return &Argon2Conf{
		Time:    conf.Time,
		Memory:  conf.Memory,
		Threads: conf.Threads,
		KeyLen:  conf.KeyLen,
	}
}

type Argon2iConf struct {
	*Argon2Conf
}

type Argon2iData struct {
	*Argon2iConf
	Salt, Key       string
	RawSalt, RawKey []byte
}

func (conf *Argon2iConf) Copy() *Argon2iConf {
	return &Argon2iConf{conf.Argon2Conf.Copy()}
}

type Argon2iHasher struct {
	*Argon2iConf
}

func NewArgon2iHasher(conf *Argon2iConf) *Argon2iHasher {
	if conf == nil {
		numCPUs := runtime.NumCPU()
		// just to be  absolutely sure we have some sensible value
		if numCPUs <= 0 || numCPUs >= math.MaxUint8 {
			numCPUs = 4
		}
		asUint := uint8(numCPUs)
		conf = &Argon2iConf{
			Argon2Conf: &Argon2Conf{Time: 3, Memory: 32 * 1024, Threads: asUint, KeyLen: 32},
		}
	}
	return &Argon2iHasher{conf}
}

func (h *Argon2iHasher) Copy() *Argon2iHasher {
	return &Argon2iHasher{h.Argon2iConf.Copy()}
}

func (h *Argon2iHasher) Key(password string, salt []byte) ([]byte, error) {
	key := argon2.Key([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	return key, nil
}

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
	result := fmt.Sprintf("$argon2i$%d$%d$%d$%d$%s$%s", argon2.Version, h.Memory, h.Time, h.Threads, saltEnc, keyEnc)
	return []byte(result), nil
}

type Argon2idConf struct {
	*Argon2Conf
}

type Argon2idData struct {
	*Argon2idConf
	// encoded with base64
	Salt, Key       string
	RawSalt, RawKey []byte
}

func (conf *Argon2idConf) Copy() *Argon2idConf {
	return &Argon2idConf{conf.Argon2Conf.Copy()}
}

type Argon2idHasher struct {
	*Argon2idConf
}

func NewArgon2idHasher(conf *Argon2idConf) *Argon2idHasher {
	if conf == nil {
		numCPUs := runtime.NumCPU()
		// just to be  absolutely sure we have some sensible value
		if numCPUs <= 0 || numCPUs >= math.MaxUint8 {
			numCPUs = 4
		}
		asUint := uint8(numCPUs)
		conf = &Argon2idConf{
			Argon2Conf: &Argon2Conf{Time: 1, Memory: 64 * 1024, Threads: asUint, KeyLen: 32},
		}
	}
	return &Argon2idHasher{conf}
}

func (h *Argon2idHasher) Copy() *Argon2idHasher {
	return &Argon2idHasher{h.Argon2idConf.Copy()}
}

func (h *Argon2idHasher) Key(password string, salt []byte) ([]byte, error) {
	key := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	return key, nil
}

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
	result := fmt.Sprintf("$argon2id$%d$%d$%d$%d$%s$%s", argon2.Version, h.Memory, h.Time, h.Threads, saltEnc, keyEnc)
	return []byte(result), nil
}

type argon2Components []string

func parseArgon2Components(s string) (argon2Components, error) {
	split := strings.Split(s, "$")
	if len(split) != 8 {
		return nil, NewSyntaxError("gopherbounce/argon2: Invalid format string (invalid number of separators)")
	}
	return split, nil
}

func (c argon2Components) getAlgorithm() string {
	return c[1]
}

func (c argon2Components) getVersion() string {
	return c[2]
}

func (c argon2Components) parseUint(s string, bitSize int) (uint64, error) {
	asUint, err := strconv.ParseUint(s, 10, bitSize)
	if err != nil {
		return math.MaxUint64, NewSyntaxError("gopherbounce/argon2: Invalid format string: Invalid integer " + err.Error())
	}
	return asUint, nil
}

func (c argon2Components) parseUint32(s string) (uint32, error) {
	parsed, err := c.parseUint(s, 32)
	if err != nil {
		return math.MaxUint32, err
	}
	return uint32(parsed), nil
}

func (c argon2Components) parseUint8(s string) (uint8, error) {
	parsed, err := c.parseUint(s, 8)
	if err != nil {
		return math.MaxUint8, err
	}
	return uint8(parsed), nil
}

func (c argon2Components) getMemory() (uint32, error) {
	return c.parseUint32(c[3])
}

func (c argon2Components) getTime() (uint32, error) {
	return c.parseUint32(c[4])
}

func (c argon2Components) getThreads() (uint8, error) {
	return c.parseUint8(c[5])
}

func (c argon2Components) getSalt() string {
	return c[6]
}

func (c argon2Components) getKey() string {
	return c[7]
}

func (c argon2Components) decode(s string) ([]byte, error) {
	dec, decErr := Base64Decode([]byte(s))
	if decErr != nil {
		return nil, NewSyntaxError("gopherbounce/argon2: Invalid format string: Invalid base64 " + decErr.Error())
	}
	return dec, nil
}

func (c argon2Components) rawSalt() ([]byte, error) {
	return c.decode(c.getSalt())
}

func (c argon2Components) rawKey() ([]byte, error) {
	return c.decode(c.getKey())
}

func (c argon2Components) getConfig() (*Argon2Conf, error) {
	var t, m uint32
	var p uint8
	var err error
	t, err = c.getTime()
	if err != nil {
		return nil, err
	}
	m, err = c.getMemory()
	if err != nil {
		return nil, err
	}
	p, err = c.getThreads()
	if err != nil {
		return nil, err
	}
	res := &Argon2Conf{
		Time:    t,
		Memory:  m,
		Threads: p,
		// Not computed here
		KeyLen: 0,
	}
	return res, nil
}

func ParseArgon2iData(hashed []byte) (*Argon2iData, error) {
	s := string(hashed)
	split, splitErr := parseArgon2Components(s)
	if splitErr != nil {
		return nil, splitErr
	}
	if split.getAlgorithm() != "argon2i" {
		return nil, NewAlgIDError("gopherbounce/argon2", "argon2i", split.getAlgorithm())
	}
	conf, confErr := split.getConfig()
	if confErr != nil {
		return nil, confErr
	}

	salt, key := split.getSalt(), split.getKey()
	rawSalt, saltErr := split.rawSalt()
	if saltErr != nil {
		return nil, saltErr
	}
	rawKey, keyErr := split.rawKey()
	if keyErr != nil {
		return nil, keyErr
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

func ParseArgon2idData(hashed []byte) (*Argon2idData, error) {
	s := string(hashed)
	split, splitErr := parseArgon2Components(s)
	if splitErr != nil {
		return nil, splitErr
	}
	if split.getAlgorithm() != "argon2id" {
		return nil, NewAlgIDError("gopherbounce/argon2", "argon2id", split.getAlgorithm())
	}
	conf, confErr := split.getConfig()
	if confErr != nil {
		return nil, confErr
	}

	salt, key := split.getSalt(), split.getKey()
	rawSalt, saltErr := split.rawSalt()
	if saltErr != nil {
		return nil, saltErr
	}
	rawKey, keyErr := split.rawKey()
	if keyErr != nil {
		return nil, keyErr
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

func (h Argon2iHasher) Compare(hashed []byte, password string) error {
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

func (h Argon2idHasher) Compare(hashed []byte, password string) error {
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
