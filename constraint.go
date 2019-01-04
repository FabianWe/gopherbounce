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
	"log"
	"strings"
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

type AccType int

const (
	Disjunction AccType = iota
	Conjunction
)

// Constraint describes a property a hasher must have.
// Usually they inclucde a restriction on the type of the hasher and
// restrictions on the hasher's parameters. Like: A bcrypt hasher with
// cost < 10. Constraints are used to find hashes the should be renewed.
// A constraints check function gets a hashed entry as input and decides
// what to do with it, like decoding it. Usually there are accumlator functions
// to avoid decoding an entry again and again.
type Constraint interface {
	Check(hashed []byte) bool
}

type AbstractBcryptConstraint interface {
	CheckBcrypt(conf *BcryptConf) bool
}

type BcryptConstraint struct {
	CostBound int64
	Rel       BinRelation
}

func NewBcryptConstraint(bound int, rel BinRelation) BcryptConstraint {
	return BcryptConstraint{
		CostBound: int64(bound),
		Rel:       rel,
	}
}

func (c BcryptConstraint) CheckBcrypt(conf *BcryptConf) bool {
	return CompareInt(int64(conf.Cost), c.CostBound, c.Rel)
}

func (c BcryptConstraint) String() string {
	return fmt.Sprintf("Cost %v %d", c.Rel, c.CostBound)
}

type BcryptAcc struct {
	Constraints []AbstractBcryptConstraint
	Type AccType
}

func NewBcryptAcc(t AccType, constraints ...AbstractBcryptConstraint) BcryptAcc {
	return BcryptAcc{
		Constraints: constraints,
		Type: t,
	}
}

func (acc BcryptAcc) CheckBcrypt(conf *BcryptConf) bool {
	switch acc.Type {
	case Disjunction:
		for _, c := range acc.Constraints {
			if c.CheckBcrypt(conf) {
				return true
			}
		}
		return false
	case Conjunction:
		for _, c := range acc.Constraints {
			if !c.CheckBcrypt(conf) {
				return false
			}
		}
		return true
	default:
		log.Printf("gopherbounce/bcrypt: Invalid accumulator type: %v\n", acc.Type)
		return false
	}
}

type AbstractScryptConstraint interface {
	CheckScrypt(data *ScryptData) bool
}

type ScryptConstraint struct {
	Bound   int64
	VarName string
	Rel     BinRelation
}

func NewScryptConstraint(bound int64, varName string, rel BinRelation) ScryptConstraint {
	return ScryptConstraint{
		Bound:   bound,
		VarName: strings.ToLower(varName),
		Rel:     rel,
	}
}

func (c ScryptConstraint) CheckScrypt(data *ScryptData) bool {
	var lhs int
	switch c.VarName {
	case "n":
		lhs = data.N
	case "r":
		lhs = data.R
	case "p":
		lhs = data.P
	case "keylen":
		lhs = data.KeyLen
	default:
		log.Printf("Invalid scrypt variable name \"%s\"\n", c.VarName)
		return false
	}
	// now lhs is set
	return CompareInt(int64(lhs), c.Bound, c.Rel)
}

func (c ScryptConstraint) String() string {
	return fmt.Sprintf("%s %v %d", c.VarName, c.Rel, c.Bound)
}

type ScryptAcc struct {
	Constraints []AbstractScryptConstraint
	Type AccType
}

func NewScryptAcc(t AccType, constraints ...AbstractScryptConstraint) ScryptAcc {
	return ScryptAcc{
		Constraints: constraints,
		Type: t,
	}
}

func (acc ScryptAcc) CheckScrypt(data *ScryptData) bool {
	switch acc.Type {
	case Disjunction:
		for _, c := range acc.Constraints {
			if c.CheckScrypt(data) {
				return true
			}
		}
		return false
	case Conjunction:
		for _, c := range acc.Constraints {
			if !c.CheckScrypt(data) {
				return false
			}
		}
		return true
	default:
		log.Printf("gopherbounce/scrypt: Invalid accumulator type: %v\n", acc.Type)
		return false
	}
}

type AbstractArgon2iConstraint interface {
	CheckArgon2i(data *Argon2iData) bool
}

type AbstractArgon2idConstraint interface {
	CheckArgon2id(data *Argon2idData) bool
}

type Argon2Constraint struct {
	Bound   uint64
	VarName string
	Rel     BinRelation
}

func NewArgon2Constraint(bound uint64, varName string, rel BinRelation) Argon2Constraint {
	return Argon2Constraint{
		Bound:   bound,
		VarName: strings.ToLower(varName),
		Rel:     rel,
	}
}

func (c Argon2Constraint) checkConf(data *Argon2Conf) bool {
	var lhs uint64
	switch c.VarName {
	case "time":
		lhs = uint64(data.Time)
	case "memory":
		lhs = uint64(data.Memory)
	case "keylen":
		lhs = uint64(data.KeyLen)
	case "threads":
		lhs = uint64(data.KeyLen)
	default:
		log.Printf("Invalid argon2 variable name \"%s\"\n", c.VarName)
		return false
	}
	// now lhs is set
	return CompareUint(lhs, c.Bound, c.Rel)
}

func (c Argon2Constraint) CheckArgon2i(data *Argon2iData) bool {
	return c.checkConf(data.Argon2Conf)
}

func (c Argon2Constraint) CheckArgon2id(data *Argon2idData) bool {
	return c.checkConf(data.Argon2Conf)
}

func (c Argon2Constraint) String() string {
	return fmt.Sprintf("%s %v %d", c.VarName, c.Rel, c.Bound)
}

type Argon2iAcc struct {
	Constraints []AbstractArgon2iConstraint
	Type AccType
}

func NewArgon2iAcc(t AccType, constraints ...AbstractArgon2iConstraint)Argon2iAcc {
	return Argon2iAcc{
		Constraints: constraints,
		Type: t,
	}
}

func (acc Argon2iAcc) CheckArgon2i(data *Argon2iData) bool{
	switch acc.Type {
	case Disjunction:
		for _, c := range acc.Constraints {
			if c.CheckArgon2i(data) {
				return true
			}
		}
		return false
	case Conjunction:
		for _, c := range acc.Constraints {
			if !c.CheckArgon2i(data) {
				return false
			}
		}
		return true
	default:
		log.Printf("gopherbounce/argon2i: Invalid accumulator type: %v\n", acc.Type)
		return false
	}
}

type Argon2idAcc struct {
	Constraints []AbstractArgon2idConstraint
	Type AccType
}

func NewArgon2idAcc(t AccType, constraints ...AbstractArgon2idConstraint)Argon2idAcc {
	return Argon2idAcc{
		Constraints: constraints,
		Type: t,
	}
}

func (acc Argon2idAcc) CheckArgon2i(data *Argon2idData) bool{
	switch acc.Type {
	case Disjunction:
		for _, c := range acc.Constraints {
			if c.CheckArgon2id(data) {
				return true
			}
		}
		return false
	case Conjunction:
		for _, c := range acc.Constraints {
			if !c.CheckArgon2id(data) {
				return false
			}
		}
		return true
	default:
		log.Printf("gopherbounce/argon2i: Invalid accumulator type: %v\n", acc.Type)
		return false
	}
}

type MultiConstraint struct {
	BcryptConstraint AbstractBcryptConstraint
	ScryptConstraint AbstractScryptConstraint
	Argon2iConstraint AbstractArgon2iConstraint
	Argon2idConstraint AbstractArgon2idConstraint
	DefaultConstraint Constraint
}

func NewMultiConstraint() *MultiConstraint {
	return &MultiConstraint{}
}

func (c *MultiConstraint) checkDefault(hashed []byte) bool {
	if c.DefaultConstraint == nil {
		return false
	}
	return c.DefaultConstraint.Check(hashed)
}

func (c *MultiConstraint ) Check(hashed []byte) bool {
	switch GuessAlg(hashed) {
	case BcryptAlg:
		if c.BcryptConstraint == nil {
			return c.checkDefault(hashed)
		}
		conf, err := ParseBcryptConf(hashed)
		if err != nil {
			log.Println("gopherbounce/constraint: Warning, can't parse bcrypt conf", err)
			return false
		}
		return c.BcryptConstraint.CheckBcrypt(conf)
	case ScryptAlg:
		if c.ScryptConstraint == nil {
			return c.checkDefault(hashed)
		}
		data, err := ParseScryptData(hashed)
		if err != nil {
			log.Println("gopherbounce/constraint: Warning, can't parse scrypt data", err)
			return false
		}
		return c.ScryptConstraint.CheckScrypt(data)
	case Argon2iAlg:
		if c.Argon2iConstraint == nil {
			return c.checkDefault(hashed)
		}
		data, err := ParseArgon2iData(hashed)
		if err != nil {
			log.Println("gopherbounce/constraint: Warning, can't parse argon2i data", err)
			return false
		}
		return c.Argon2iConstraint.CheckArgon2i(data)
	case Argon2idAlg:
		if c.Argon2idConstraint == nil {
			return c.checkDefault(hashed)
		}
		data, err := ParseArgon2idData(hashed)
		if err != nil {
			log.Println("gopherbounce/constraint: Warning, can't parse argon2id data", err)
			return false
		}
		return c.Argon2idConstraint.CheckArgon2id(data)
	default:
		return c.checkDefault(hashed)
	}
}
