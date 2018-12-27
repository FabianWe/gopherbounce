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

	"golang.org/x/crypto/argon2"
)

type Argon2iHasher struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

func NewArgon2iHasher() *Argon2iHasher {
	numCPUs := runtime.NumCPU()
	// just to be  absolutely sure we have some sensible value
	if numCPUs <= 0 || numCPUs >= math.MaxUint8 {
		numCPUs = 4
	}
	asUint := uint8(numCPUs)
	return &Argon2iHasher{Time: 3, Memory: 32 * 1024, Threads: asUint, KeyLen: 32}
}

func (h *Argon2iHasher) Generate(password string) ([]byte, error) {
	salt, saltErr := GenSalt(int(h.KeyLen))
	if saltErr != nil {
		return nil, saltErr
	}
	key := argon2.Key([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	// encode salt and key
	saltEnc, keyEnc := Base64Encode(salt), Base64Encode(key)
	result := fmt.Sprintf("$argon2i$%d$%d$%d$%d$%s$%s", argon2.Version, h.Memory, h.Time, h.Threads, saltEnc, keyEnc)
	return []byte(result), nil
}

type Argon2idHasher struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

func NewArgon2idHasher() *Argon2idHasher {
	numCPUs := runtime.NumCPU()
	// just to be  absolutely sure we have some sensible value
	if numCPUs <= 0 || numCPUs >= math.MaxUint8 {
		numCPUs = 4
	}
	asUint := uint8(numCPUs)
	return &Argon2idHasher{Time: 1, Memory: 64 * 1024, Threads: asUint, KeyLen: 32}
}

func (h *Argon2idHasher) Generate(password string) ([]byte, error) {
	salt, saltErr := GenSalt(int(h.KeyLen))
	if saltErr != nil {
		return nil, saltErr
	}
	key := argon2.IDKey([]byte(password), salt, h.Time, h.Memory, h.Threads, h.KeyLen)
	// encode salt and key
	saltEnc, keyEnc := Base64Encode(salt), Base64Encode(key)
	result := fmt.Sprintf("$argon2id$%d$%d$%d$%d$%s$%s", argon2.Version, h.Memory, h.Time, h.Threads, saltEnc, keyEnc)
	return []byte(result), nil
}

func (h *Argon2idHasher) Encode(hash []byte) (string, error) {
	return string(hash), nil
}
