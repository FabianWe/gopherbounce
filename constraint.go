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

// BinRelation is a type used to identify relations on integers (<, = etc.).
type BinRelation int

const (
	// Less describes the relation <.
	Less BinRelation = iota
	// Greater describes the relation >.
	Greater
	// Leq describes the relation ≤.
	Leq
	// Geq describes the relation ≥.
	Geq
	// Eq describes the equality relation =.
	Eq
)

// ParseRelation parses the relation type from a string.
// It accepts the "obvious" symbols like <, >=, =.
// It also accepts ≤ and ≥.
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

// CompareInt compares two integers given the relation.
// For example CompareInt(21, 42, Less) would return true.
// For an unkown relation it returns false and logs a warning.
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

// CompareUint compares to uints given the relation.
// It works as CompareInt, but works with uints instead of ints.
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

// Constraint describes a property a hasher must have.
// Usually they inclucde a restriction on the type of the hasher and
// restrictions on the hasher's parameters. Like: A bcrypt hasher with
// cost < 10. Constraints are used to find hashes the should be renewed.
type Constraint func(Hasher) bool

// MakeConjunction returns a new constraint that is the conjunction of other
// constraints. That is all constraints must be true in order for the
// conjunction to be true.
// If constraints is empty a conjunction always returns false and logs a
// warning.
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

// MakeDisjunction returns a new constraint that is the disjunction of other
// constraints. That is: If one constraint is true the disjunction returns true.
// If constraints is empty the disjunction always returns false.
func MakeDisjunction(constraints ...Constraint) Constraint {
	return func(h Hasher) bool {
		for _, c := range constraints {
			if c(h) {
				return true
			}
		}
		return false
	}
}

// BcryptConstraint is a constraint based on a bcrypt hasher.
type BcryptConstraint func(BcryptHasher) bool

// MakeBcryptConstraint transforms a BcryptConstraint to a general Constraint.
// It performs a type check and applies the wrapped constraint if the hasher is
// a bcrypt hasher.
func MakeBcryptConstraint(c BcryptConstraint) Constraint {
	return func(h Hasher) bool {
		bHasher, ok := h.(BcryptHasher)
		if !ok {
			return false
		}
		return c(bHasher)
	}
}

// BcryptCostConstraint is a constraint that checks if cost RELATION bound.
func BcryptCostConstraint(bound int, relation BinRelation) BcryptConstraint {
	return func(h BcryptHasher) bool {
		return CompareInt(int64(h.Cost), int64(bound), relation)
	}
}

// ScryptConstraint is a constraint based on a scrypt hasher.
type ScryptConstraint func(*ScryptHasher) bool

// MakeScryptConstraint transforms a ScryptConstraint to a general Constraint.
// It performs a type check and applies the wrapped constraint if the hasher is
// a scrypt hasher.
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

// ScryptNConstraint is a constraint that checks if N RELATION bound.
func ScryptNConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.N
	}
	return scryptIntConstraint(selector, bound, relation)
}

// ScryptRConstraint is a constraint that checks if R RELATION bound.
func ScryptRConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.R
	}
	return scryptIntConstraint(selector, bound, relation)
}

// ScryptPConstraint is a constraint that checks if P RELATION bound.
func ScryptPConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.P
	}
	return scryptIntConstraint(selector, bound, relation)
}

// ScryptKeyLenConstraint is a constraint that checks if KeyLen RELATION bound.
func ScryptKeyLenConstraint(bound int, relation BinRelation) ScryptConstraint {
	selector := func(h *ScryptHasher) int {
		return h.KeyLen
	}
	return scryptIntConstraint(selector, bound, relation)
}

// Argon2Constraint is a constraint based on an argon2 hasher (argon2i or
// argon2id). It is actually based on the conf of the hashers (since both Hasher
// implementations share the same conf).
type Argon2Constraint func(*Argon2Conf) bool

// MakeArgon2iConstraint transforms a Argon2Constraint to a general Constraint.
// It performs a type check and applies the wrapped constraint if the hasher is
// an argon2i hasher.
func MakeArgon2iConstraint(c Argon2Constraint) Constraint {
	return func(h Hasher) bool {
		aHasher, ok := h.(*Argon2iHasher)
		if !ok {
			return false
		}
		return c(aHasher.Argon2Conf)
	}
}

// MakeArgon2idConstraint transforms a Argon2Constraint to a general Constraint.
// It performs a type check and applies the wrapped constraint if the hasher is
// an argon2id hasher.
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

// Argon2TimeConstraint is a constraint that checks if Time RELATION bound.
func Argon2TimeConstraint(bound uint32, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint32 {
		return c.Time
	}
	return argon2Uint32Constraint(selector, bound, relation)
}

// Argon2MemoryConstraint is a constraint that checks if Memory RELATION bound.
func Argon2MemoryConstraint(bound uint32, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint32 {
		return c.Memory
	}
	return argon2Uint32Constraint(selector, bound, relation)
}

// Argon2KeyLenConstraint is a constraint that checks if KeyLen RELATION bound.
func Argon2KeyLenConstraint(bound uint32, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint32 {
		return c.KeyLen
	}
	return argon2Uint32Constraint(selector, bound, relation)
}

// Argon2ThreadsConstraint is a constraint that checks if
// Threads RELATION bound.
func Argon2ThreadsConstraint(bound uint8, relation BinRelation) Argon2Constraint {
	selector := func(c *Argon2Conf) uint8 {
		return c.Threads
	}
	return argon2Uint8Constraint(selector, bound, relation)
}

// ConstraintInfo describes "meta" information about constraints. Because
// constraints are functions it's not easy to get a human readable version
// of a constraint. This type helps with that. The left-hand side describes
// the variable name used for the relation (like "Cost") and the right-hand side
// the bound of the constraint. For example the constraint cost < 10 would be
// described as {"cost" 10 Less}.
type ConstraintInfo struct {
	LHS      string
	RHS      interface{}
	Relation BinRelation
}

// NewConstraintInfo returns a new constraint info.
func NewConstraintInfo(lhs string, rhs interface{}, rel BinRelation) *ConstraintInfo {
	return &ConstraintInfo{
		LHS:      lhs,
		RHS:      rhs,
		Relation: rel,
	}
}
