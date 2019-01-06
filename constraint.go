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

// AccType is an accumlator type used to combine constraints.
// Constraints can be a Conjunction (and) or Disjunction (or).
type AccType int

const (
	// Disjunction is an or connection.
	Disjunction AccType = iota
	// Conjunction is an and connection. Note that an empty Conjunction is always
	// true.
	Conjunction
)

// Constraint describes a property a hasher must have.
// Usually they inclucde a restriction on the type of the hasher and
// restrictions on the hasher's parameters. Like: A bcrypt hasher with
// cost < 10. Constraints are used to find hashes that should be renewed /
// replaced.
// A constraints check function gets a hashed entry as input and decides
// what to do with it, like decoding it. Usually there are accumlator functions
// to avoid decoding an entry again and again.
type Constraint interface {
	Check(hashed []byte) bool
}

// ConstraintConjunction is a conjunction of Constraints and itself implements
// the Constraint interface. An empty conjunction is considered true.
type ConstraintConjunction []Constraint

// NewConstraintConjunction returns a new conjunction.
func NewConstraintConjunction(constraints ...Constraint) ConstraintConjunction {
	return ConstraintConjunction(constraints)
}

// Check checks if all conjuncts are true.
func (conj ConstraintConjunction) Check(hashed []byte) bool {
	for _, conjunct := range conj {
		if !conjunct.Check(hashed) {
			return false
		}
	}
	return true
}

// ConstraintDisjunction is a disjunction of Constraints and itself implements
// the Constraint interface.
type ConstraintDisjunction []Constraint

// NewConstraintDisjunction returns a new disjunction.
func NewConstraintDisjunction(constraints ...Constraint) ConstraintDisjunction {
	return ConstraintDisjunction(constraints)
}

// Check checks if at least one disjunct is true.
func (disj ConstraintDisjunction) Check(hashed []byte) bool {
	for _, conjunct := range disj {
		if conjunct.Check(hashed) {
			return true
		}
	}
	return false
}

// AbstractBcryptConstraint is a constraint based on bcrypt configs.
type AbstractBcryptConstraint interface {
	CheckBcrypt(conf *BcryptConf) bool
}

// BcryptConstraint implements AbstractBcryptConstraint and imposes a
// restriction on the cost of the config.
type BcryptConstraint struct {
	CostBound int64
	Rel       BinRelation
}

// NewBcryptConstraint returns a new BcryptConstraint.
func NewBcryptConstraint(bound int, rel BinRelation) BcryptConstraint {
	return BcryptConstraint{
		CostBound: int64(bound),
		Rel:       rel,
	}
}

// CheckBcrypt checks the cost according to the provided relation.
func (c BcryptConstraint) CheckBcrypt(conf *BcryptConf) bool {
	return CompareInt(int64(conf.Cost), c.CostBound, c.Rel)
}

func (c BcryptConstraint) String() string {
	return fmt.Sprintf("Cost %v %d", c.Rel, c.CostBound)
}

// BcryptAcc is an accumulation of bcrypt constraints.
// It implements AbstractBcryptConstraint.
type BcryptAcc struct {
	Constraints []AbstractBcryptConstraint
	Type        AccType
}

// NewBcryptAcc returns a new BcryptAcc given the accumulation type and
// the constraints it's composed of.
func NewBcryptAcc(t AccType, constraints ...AbstractBcryptConstraint) BcryptAcc {
	return BcryptAcc{
		Constraints: constraints,
		Type:        t,
	}
}

// CheckBcrypt composes the constraints based on the accumulation type.
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

// AbstractScryptConstraint is a constraint based on scrypt data.
type AbstractScryptConstraint interface {
	CheckScrypt(data *ScryptData) bool
}

// ScryptConstraint implements AbstractScryptConstraint and imposes a
// restriction on one of the parameters. The parameter is describec by the
// string name.
// It imposes the restriction [VarName] [Rel] [Bound]. For example
// n < 32768.
//
// Note that n = 2^(rounds).
//
// VarName must be either n, rounds, r, p or KeyLen.
type ScryptConstraint struct {
	Bound   int64
	VarName string
	Rel     BinRelation
}

// NewScryptConstraint returns a new ScryptConstraint. It does not check if
// varName is valid.
func NewScryptConstraint(bound int64, varName string, rel BinRelation) ScryptConstraint {
	return ScryptConstraint{
		Bound:   bound,
		VarName: strings.ToLower(varName),
		Rel:     rel,
	}
}

// CheckScrypt checks the scrypt data based on the variable name, relation
// and bound.
func (c ScryptConstraint) CheckScrypt(data *ScryptData) bool {
	var lhs int
	switch c.VarName {
	case "n":
		lhs = data.GetN()
	case "rounds":
		lhs = data.GetRounds()
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

// ScryptAcc is an accumulation of bcrypt constraints.
// It implements AbstractScryptConstraint.
type ScryptAcc struct {
	Constraints []AbstractScryptConstraint
	Type        AccType
}

// NewScryptAcc returns a new ScryptAcc given the accumulation type and
// the constraints it's composed of.
func NewScryptAcc(t AccType, constraints ...AbstractScryptConstraint) ScryptAcc {
	return ScryptAcc{
		Constraints: constraints,
		Type:        t,
	}
}

// CheckScrypt composes the constraints based on the accumulation type.
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

// AbstractArgon2iConstraint is a constraint based on argon2i data.
type AbstractArgon2iConstraint interface {
	CheckArgon2i(data *Argon2iData) bool
}

// AbstractArgon2idConstraint is a constraint based on argon2id data.
type AbstractArgon2idConstraint interface {
	CheckArgon2id(data *Argon2idData) bool
}

// Argon2Constraint imposes a restriction on one of the parameters of
// an Argon2Conf. The parameter is describec by the string name.
// It imposes the restriction [VarName] [Rel] [Bound]. For example
// time < 2.
//
// It implements both AbstractArgon2iConstraint and AbstractArgon2idConstraint.
//
// VarName must be either "time", "memory", "keylen" or "threads".
type Argon2Constraint struct {
	Bound   uint64
	VarName string
	Rel     BinRelation
}

// NewArgon2Constraint returns a new Argon2Constraint. It does not check if
// varName is valid.
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

// // CheckArgon2i checks the argon2 data based on the variable name, relation
// and bound.
func (c Argon2Constraint) CheckArgon2i(data *Argon2iData) bool {
	return c.checkConf(data.Argon2Conf)
}

// CheckArgon2id checks the argon2 data based on the variable name, relation
// and bound.
func (c Argon2Constraint) CheckArgon2id(data *Argon2idData) bool {
	return c.checkConf(data.Argon2Conf)
}

func (c Argon2Constraint) String() string {
	return fmt.Sprintf("%s %v %d", c.VarName, c.Rel, c.Bound)
}

// Argon2iAcc is an accumulation of argon2i constraints.
// It implements AbstractArgon2iConstraint.
type Argon2iAcc struct {
	Constraints []AbstractArgon2iConstraint
	Type        AccType
}

// NewArgon2iAcc returns a new Argon2iAcc given the accumulation type and
// the constraints it's composed of.
func NewArgon2iAcc(t AccType, constraints ...AbstractArgon2iConstraint) Argon2iAcc {
	return Argon2iAcc{
		Constraints: constraints,
		Type:        t,
	}
}

// CheckArgon2i composes the constraints based on the accumulation type.
func (acc Argon2iAcc) CheckArgon2i(data *Argon2iData) bool {
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

// Argon2idAcc is an accumulation of argon2id constraints.
// It implements AbstractArgon2idConstraint.
type Argon2idAcc struct {
	Constraints []AbstractArgon2idConstraint
	Type        AccType
}

// NewArgon2idAcc returns a new Argon2idAcc given the accumulation type and
// the constraints it's composed of.
func NewArgon2idAcc(t AccType, constraints ...AbstractArgon2idConstraint) Argon2idAcc {
	return Argon2idAcc{
		Constraints: constraints,
		Type:        t,
	}
}

// CheckArgon2id composes the constraints based on the accumulation type.
func (acc Argon2idAcc) CheckArgon2id(data *Argon2idData) bool {
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

// MultiConstraint composes the basic constraint types (bcrypt, scrypt argon2i
// and argon2id).
// It implements the general Constraint interface.
//
// It's behaviour is as follows: It checks the hashed string and decides
// which algorithm it belongs to.
// First it checks if there is a general constraint for this algorithm.
// For example if bcrypt should be completely ignored you can use
// AddAlgConstraint(BcryptAlg). If this is the case it returns true.
// Otherwise it decodes the config / data from the hash and passes it to the
// corresponding constraint.
//
// For example bcrypt hashes (beginning with $2a$) are passed to the
// BcryptConstraint. The config is parsed from that hash.
//
// It also has a "fallback" constraint that is applied if the hashing algorithm
// is unkown.
type MultiConstraint struct {
	algConstraints     map[HashAlg]struct{}
	BcryptConstraint   AbstractBcryptConstraint
	ScryptConstraint   AbstractScryptConstraint
	Argon2iConstraint  AbstractArgon2iConstraint
	Argon2idConstraint AbstractArgon2idConstraint
	DefaultConstraint  Constraint
}

// NewMultiConstraint returns a new MultiConstraint where all constraints are
// set to nil, that is it always returns false.
func NewMultiConstraint() *MultiConstraint {
	return &MultiConstraint{
		algConstraints: make(map[HashAlg]struct{}, 4),
	}
}

// AddAlgConstraint adds a constraint that all hashes of algorithm alg should
// be ignored.
func (c *MultiConstraint) AddAlgConstraint(alg HashAlg) {
	c.algConstraints[alg] = struct{}{}
}

// RemoveAlgConstraint removes the constraint that all hashes of algorithm
// alg should be ignored.
func (c *MultiConstraint) RemoveAlgConstraint(alg HashAlg) {
	delete(c.algConstraints, alg)
}

// HasAlgConstraint checks if there is a constraint that all hashes of algorithm
// alg should be ignored.
func (c *MultiConstraint) HasAlgConstraint(alg HashAlg) bool {
	_, has := c.algConstraints[alg]
	return has
}

func (c *MultiConstraint) checkDefault(hashed []byte) bool {
	if c.DefaultConstraint == nil {
		return false
	}
	return c.DefaultConstraint.Check(hashed)
}

// Check implements the Constraint interface.
func (c *MultiConstraint) Check(hashed []byte) bool {
	guess := GuessAlg(hashed)
	// if there is a constraint that this algorithm should be completely
	// ignored return true
	if c.HasAlgConstraint(guess) {
		return true
	}
	switch guess {
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

// AlgConstraint implements Constraint and only tests if the hashed string
// represents a specific type.
type AlgConstraint HashAlg

// NewAlgConstraint returns a new AlgConstraint that returns true if the
// algorithm represented by a hashed password is alg.
func NewAlgConstraint(alg HashAlg) AlgConstraint {
	return AlgConstraint(alg)
}

// Check implements the Constraint interface.
func (c AlgConstraint) Check(hashed []byte) bool {
	guess := GuessAlg(hashed)
	return guess == HashAlg(c)
}
