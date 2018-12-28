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
	"log"
)

type BinRelation int

const (
	Less BinRelation = iota
	Greater
	Leq
	Geq
	Eq
)

func ParseRelation(s string) (BinRelation, error) {
	switch s {
	case "<":
		return Less, nil
	case ">":
		return Greater, nil
	case "<=", "≤":
		return Leq, nil
	case ">=", "≥":
		return Geq, nil
	case "=", "==":
		return Eq, nil
	default:
		return -1, fmt.Errorf("Unkown relation symbol: %s", s)
	}
}

func (rel BinRelation) String() string {
	switch rel {
	case Less:
		return "<"
	case Greater:
		return ">"
	case Leq:
		return "≤"
	case Geq:
		return "≥"
	case Eq:
		return "="
	default:
		return fmt.Sprintf("BinRelation(%d)", rel)
	}
}

func CompareInt(a, b int64, rel BinRelation) bool {
	switch rel {
	case Less:
		return a < b
	case Greater:
		return a > b
	case Leq:
		return a <= b
	case Geq:
		return a >= b
	case Eq:
		return a == b
	default:
		log.Printf("Warning: Invalid integer relation: %v\n", rel)
		return false
	}
}

func CompareUint(a, b uint64, rel BinRelation) bool {
	switch rel {
	case Less:
		return a < b
	case Greater:
		return a > b
	case Leq:
		return a <= b
	case Geq:
		return a >= b
	case Eq:
		return a == b
	default:
		log.Printf("Warning: Invalid unsigned integer relation: %v\n", rel)
		return false
	}
}

type Constraint func(Hasher) bool

func MakeConjunction(constraints ...Constraint) Constraint {
	if len(constraints) == 0 {
		log.Println("Warning: Empty conjunction, returning false")
		return func(Hasher) bool {
			return false
		}
	}
	return func(h Hasher) bool {
		for _, c := range constraints {
			if !c(h) {
				return false
			}
		}
		return true
	}
}

type BcryptConstraint func(BcryptHasher) bool

func MakeBcryptConstraint(c BcryptConstraint) Constraint {
	return func(h Hasher) bool {
		bHasher, ok := h.(BcryptHasher)
		if !ok {
			return false
		}
		return c(bHasher)
	}
}

func BcryptCostConstraint(bound int, relation BinRelation) BcryptConstraint {
	return func(h BcryptHasher) bool {
		return CompareInt(int64(h.Cost), int64(bound), relation)
	}
}

type ScryptConstraint func(*ScryptHasher) bool

func MakeScryptConstraint(c ScryptConstraint) Constraint {
	return func(h Hasher) bool {
		sHasher, ok := h.(*ScryptHasher)
		if !ok {
			return false
		}
		return c(sHasher)
	}
}

func scryptIntConstraint(selector func(*ScryptHasher) int, bound int, relation BinRelation) ScryptConstraint {
	return func(h *ScryptHasher) bool {
		a := int64(selector(h))
		b := int64(bound)
		return CompareInt(a, b, relation)
	}
}

func ScryptNConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.N
	}
	return scryptIntConstraint(selector, bound, relation)
}

func ScryptRConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.R
	}
	return scryptIntConstraint(selector, bound, relation)
}

func ScryptPConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.P
	}
	return scryptIntConstraint(selector, bound, relation)
}

func ScryptKeyLenConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.KeyLen
	}
	return scryptIntConstraint(selector, bound, relation)
}

type Argon2Constraint func(*Argon2Conf) bool

func MakeArgon2iConstraint(c Argon2Constraint) Constraint {
	return func(h Hasher) bool {
		aHasher, ok := h.(*Argon2iHasher)
		if !ok {
			return false
		}
		return c(aHasher.Argon2Conf)
	}
}

func MakeArgon2idConstraint(c Argon2Constraint) Constraint {
	return func(h Hasher) bool {
		aHasher, ok := h.(*Argon2idHasher)
		if !ok {
			return false
		}
		return c(aHasher.Argon2Conf)
	}
}

func argon2Uint32Constraint(selector func(*Argon2Conf) uint32, bound uint32, relation BinRelation) Argon2Constraint {
	return func(c *Argon2Conf) bool {
		a := uint64(selector(c))
		b := uint64(bound)
		return CompareUint(a, b, relation)
	}
}

func argon2Uint8Constraint(selector func(*Argon2Conf) uint8, bound uint8, relation BinRelation) Argon2Constraint {
	return func(c *Argon2Conf) bool {
		a := uint64(selector(c))
		b := uint64(bound)
		return CompareUint(a, b, relation)
	}
}

func Argon2TimeConstraint(bound uint32, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint32 {
		return c.Time
	}
	return argon2Uint32Constraint(selector, bound, relation)
}

func Argon2MemoryConstraint(bound uint32, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint32 {
		return c.Memory
	}
	return argon2Uint32Constraint(selector, bound, relation)
}

func Argon2KeyLenConstraint(bound uint32, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint32 {
		return c.KeyLen
	}
	return argon2Uint32Constraint(selector, bound, relation)
}

func Argon2ThreadsConstraint(bound uint8, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint8 {
		return c.Threads
	}
	return argon2Uint8Constraint(selector, bound, relation)
}

type ConstraintInfo struct {
	Lhs      string
	Rhs      interface{}
	Relation BinRelation
}

func NewConstraintInfo(lhs string, rhs interface{}, rel BinRelation) *ConstraintInfo {
	return &ConstraintInfo{
		Lhs:      lhs,
		Rhs:      rhs,
		Relation: rel,
	}
}
