// Copyright 2019 Fabian Wenzelmann
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
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func setArgon2Val(conf *Argon2Conf, name string, value uint64) error {
	switch name {
	case "time":
		conf.Time = uint32(value)
	case "memory":
		conf.Memory = uint32(value)
	case "keylen":
		conf.KeyLen = uint32(value)
	case "threads":
		conf.Threads = uint8(value)
	default:
		return fmt.Errorf("Internal error in ParseHasher: Invalid argon2 value %s", name)
	}
	return nil
}

// ParseHasher parses a hasher from a config file.
// The syntax is the same as for constraint, but the relation must be =.
func ParseHasher(r io.Reader) (Hasher, error) {
	scanner := bufio.NewScanner(r)
	first := true
	var line string
	var res Hasher
	for scanner.Scan() {
		line = strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if first {
			first = false
			// parse alg line
			algStr, _, algErr := ParseHeadLine(line)
			if algErr != nil {
				return nil, NewConstraintSyntaxError(algErr.Error())
			}
			alg, algErr := ParseAlg(algStr)
			if algErr != nil {
				return nil, NewConstraintSyntaxError(algErr.Error())
			}
			switch alg {
			case BcryptAlg:
				res = NewBcryptHasher(nil)
			case ScryptAlg:
				res = NewScryptHasher(nil)
			case Argon2iAlg:
				res = NewArgon2iHasher(nil)
			case Argon2idAlg:
				res = NewArgon2idHasher(nil)
			default:
				return nil, fmt.Errorf("Invalid algorithm: %s", alg)
			}
		} else {
			// algorithm has been parsed, check which one it is
			switch h := res.(type) {
			case *BcryptHasher:
				c, cErr := ParseBcryptCons(line)
				if cErr != nil {
					return nil, cErr
				}
				if c.Rel != Eq {
					return nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid relation %s, must be =", c.Rel))
				}
				cost := int(c.CostBound)
				h.Cost = cost
			case *ScryptHasher:
				c, cErr := ParseScryptCons(line)
				if cErr != nil {
					return nil, cErr
				}
				if c.Rel != Eq {
					return nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid relation %s, must be =", c.Rel))
				}
				switch c.VarName {
				case "n":
					return nil, errors.New("N is not a configurable parameter for scrypt, use rounds = ... instead")
				case "rounds":
					h.SetRounds(int(c.Bound))
				case "r":
					h.R = int(c.Bound)
				case "p":
					h.P = int(c.Bound)
				case "keylen":
					h.KeyLen = int(c.Bound)
				default:
					return nil, fmt.Errorf("Internal error in ParseHasher: Invalid scrypt value %s", c.VarName)
				}
			case *Argon2iHasher:
				c, cErr := ParseArgon2Cons(line)
				if cErr != nil {
					return nil, cErr
				}
				if c.Rel != Eq {
					return nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid relation %s, must be =", c.Rel))
				}
				if err := setArgon2Val(h.Argon2Conf, c.VarName, c.Bound); err != nil {
					return nil, err
				}
			case *Argon2idHasher:
				c, cErr := ParseArgon2Cons(line)
				if cErr != nil {
					return nil, cErr
				}
				if c.Rel != Eq {
					return nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid relation %s, must be =", c.Rel))
				}
				if err := setArgon2Val(h.Argon2Conf, c.VarName, c.Bound); err != nil {
					return nil, err
				}
			default:
				return nil, errors.New("Internal error in ParseHasher: Invalid hasher type found")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

// ParseHasherConfFile works as ParseHasher and reads the content from a file.
func ParseHasherConfFile(path string) (Hasher, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseHasher(f)
}

func WriteHasherConfig(w io.Writer, hasher Hasher) (int, error) {
	if hasher == nil {
		return 0, errors.New("Can't write nil hasher")
	}
	res := 0

	return res, nil
}
