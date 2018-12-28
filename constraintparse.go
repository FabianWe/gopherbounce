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
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ConstraintSyntaxError is an error returned if an error occurred due to a
// invalid syntax while parsing constraints.
type ConstraintSyntaxError string

// NewConstraintSyntaxError returns a new ConstraintSyntaxError.
func NewConstraintSyntaxError(cause string) ConstraintSyntaxError {
	return ConstraintSyntaxError(cause)
}

func (err ConstraintSyntaxError) Error() string {
	return "Syntax error: " + string(err)
}

var (
	// ConstraintLineRx is the regex used to parse a single constraint line.
	ConstraintLineRx = regexp.MustCompile(`^\s*([a-zA-Z]+)\s+(<|>|<=|>=|=|≤|≥)\s+(-?\d+)\s*$`)
	// HeadLineRx is the regex used to parse a heading line.
	HeadLineRx = regexp.MustCompile(`^\s*\[\s*(\w+)(\s*=\s*(\w+))?\s*\]\s*$`)
)

// ParseConstraintLine parses a single line constraint line (with
// ConstraintLineRx).
// It returns the lhs and rhs as a string.
// Example of a line "cost < 10" that would return "cost" "10" Less.
func ParseConstraintLine(line string) (lhs, rhs string, rel BinRelation, err error) {
	match := ConstraintLineRx.FindStringSubmatch(line)
	if len(match) == 0 {
		err = NewConstraintSyntaxError("Can't match line")
		return
	}
	rel, err = ParseRelation(match[2])
	if err != nil {
		err = NewConstraintSyntaxError(err.Error())
		return
	}
	lhs, rhs = match[1], match[3]
	return
}

// ParseHeadLine parses a heading line (with HeadLineRx).
// Example of a line "[bcypt]" or with a name [scrypt = foo].
// The first one yields to "bcrypt" and the empty string, the second to
// "scrypt" and "foo".
func ParseHeadLine(line string) (algorithm, name string, err error) {
	match := HeadLineRx.FindStringSubmatch(line)
	fmt.Println("Match len:", len(match))
	switch len(match) {
	case 0:
		err = NewConstraintSyntaxError("Can't match line")
	case 4:
		algorithm, name = match[1], match[3]
	default:
		err = fmt.Errorf("Internal error: Regex match in gopherbounce.ParseHeadLine has length %d", len(match))
	}
	return
}

// ParseConstraintInt works as ParseConstraintLine but the right-hand side
// is parsed into a int64 (with the given bitSize).
func ParseConstraintInt(line string, bitSize int) (lhs string, rhs int64, rel BinRelation, err error) {
	var rhsString string
	lhs, rhsString, rel, err = ParseConstraintLine(line)
	if err != nil {
		return
	}
	// parse rhs
	rhs, err = strconv.ParseInt(rhsString, 10, bitSize)
	if err != nil {
		err = NewConstraintSyntaxError(err.Error())
	}
	return
}

// ParseConstraintUint works as ParseConstraintInt but parses a uint.
func ParseConstraintUint(line string, bitSize int) (lhs string, rhs uint64, rel BinRelation, err error) {
	var rhsString string
	lhs, rhsString, rel, err = ParseConstraintLine(line)
	if err != nil {
		return
	}
	// parse rhs
	rhs, err = strconv.ParseUint(rhsString, 10, bitSize)
	if err != nil {
		err = NewConstraintSyntaxError(err.Error())
	}
	return
}

// ParseBcryptCons parses a constraint for bcrypt. The only allowed form is
// "cost RELATION BOUND".
func ParseBcryptCons(line string) (BcryptConstraint, *ConstraintInfo, error) {
	lhs, bound64, rel, err := ParseConstraintInt(line, strconv.IntSize)
	if err != nil {
		return nil, nil, err
	}
	bound := int(bound64)
	switch strings.ToLower(lhs) {
	case "cost", "c":
		return BcryptCostConstraint(bound, rel), NewConstraintInfo("cost", bound, rel), nil
	default:
		return nil, nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid left-hand side of relation, must be \"cost\", got %s", lhs))
	}
}

// ParseScryptCons parses a constraint for scrypt. It allows the following
// format: "LHS RELATION BOUND" where LHS is either "N", "R", "P" or "KeyLen".
func ParseScryptCons(line string) (ScryptConstraint, *ConstraintInfo, error) {
	lhs, bound64, rel, err := ParseConstraintInt(line, strconv.IntSize)
	if err != nil {
		return nil, nil, err
	}
	bound := int(bound64)
	switch strings.ToLower(lhs) {
	case "n":
		return ScryptNConstraint(bound, rel), NewConstraintInfo("N", bound, rel), nil
	case "r":
		return ScryptRConstraint(bound, rel), NewConstraintInfo("R", bound, rel), nil
	case "p":
		return ScryptPConstraint(bound, rel), NewConstraintInfo("P", bound, rel), nil
	case "keylen", "len":
		return ScryptKeyLenConstraint(bound, rel), NewConstraintInfo("KeyLen", bound, rel), nil
	default:
		return nil, nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid left-hand side of relation, must be N, R, P or KeyLen, got %s", lhs))
	}
}

// ParseArgon2Cons parses a constraint for argon2 (argon2i and argon2id). It
// allows the following format: "LHS RELATION BOUND" where LHS is either "time",
// "memory", "Threads" or "KeyLen".
func ParseArgon2Cons(line string) (Argon2Constraint, *ConstraintInfo, error) {
	lhs, rhsStr, rel, err := ParseConstraintLine(line)
	if err != nil {
		return nil, nil, err
	}
	var bound64 uint64
	switch strings.ToLower(lhs) {
	case "time", "t":
		bound64, err = strconv.ParseUint(rhsStr, 10, 32)
		if err != nil {
			return nil, nil, NewConstraintSyntaxError(err.Error())
		}
		bound := uint32(bound64)
		return Argon2TimeConstraint(bound, rel), NewConstraintInfo("Time", bound, rel), nil
	case "memory", "m":
		bound64, err = strconv.ParseUint(rhsStr, 10, 32)
		if err != nil {
			return nil, nil, NewConstraintSyntaxError(err.Error())
		}
		bound := uint32(bound64)
		return Argon2MemoryConstraint(bound, rel), NewConstraintInfo("Memory", bound, rel), nil
	case "keylen", "len":
		bound64, err = strconv.ParseUint(rhsStr, 10, 32)
		if err != nil {
			return nil, nil, NewConstraintSyntaxError(err.Error())
		}
		bound := uint32(bound64)
		return Argon2KeyLenConstraint(bound, rel), NewConstraintInfo("KeyLen", bound, rel), nil
	case "threads", "p":
		bound64, err = strconv.ParseUint(rhsStr, 10, 8)
		if err != nil {
			return nil, nil, NewConstraintSyntaxError(err.Error())
		}
		bound := uint8(bound64)
		return Argon2ThreadsConstraint(bound, rel), NewConstraintInfo("Threads", bound, rel), nil
	default:
		return nil, nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid left-hand side of relation, must be time, memory, threads or KeyLen, got %s", lhs))
	}
}

// ConstraintBlock describes a block of constraints. A block consists of the
// algorithm type (for example bcrypt) and all constraints for that algorithm.
// Constraints and Infos are always of the same length and Infos[i] describes
// the meta information for Constraints[i].
type ConstraintBlock struct {
	Algorithm   string
	Name        string
	Constraints []Constraint
	Infos       []*ConstraintInfo
}

// NewConstraintBlock returns a new box without constraints and infos.
func NewConstraintBlock(algorithm, name string) *ConstraintBlock {
	return &ConstraintBlock{
		Algorithm:   algorithm,
		Name:        name,
		Constraints: make([]Constraint, 0),
		Infos:       make([]*ConstraintInfo, 0),
	}
}

// ParseConstraints parses all blocks from a reader, see the README for more
// details.
func ParseConstraints(r io.Reader) ([]*ConstraintBlock, error) {
	result := make([]*ConstraintBlock, 0)
	scanner := bufio.NewScanner(r)
	state := 0
	var lastBlock *ConstraintBlock
L:
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch state {
		case 0:
			if len(line) == 0 || strings.HasPrefix(line, "#") {
				continue L
			}
			// must be a valid heading
			algorithm, name, err := ParseHeadLine(line)
			if err != nil {
				return nil, err
			}
			switch algorithm {
			case BcryptName, ScryptName, Argon2iName, Argon2idName:
				newBlock := NewConstraintBlock(algorithm, name)
				result = append(result, newBlock)
				lastBlock = newBlock
				state = 1
			default:
				return nil, NewConstraintSyntaxError("Invalid algorithm name")
			}
		case 1:
			// now we must either parse an empty line (meaning end of block)
			// or a constraint
			if strings.HasPrefix(line, "#") {
				continue L
			}
			if len(line) == 0 {
				// now we must finish the current box, that is we check if it is not
				// empty, switch to state 0 and continue the loop

				// this should no thappen
				if lastBlock == nil {
					return nil, fmt.Errorf("Internal error: Invalid configuration while parsing")
				}
				if len(lastBlock.Constraints) == 0 {
					return nil, NewConstraintSyntaxError(fmt.Sprintf("No constraints in block for %s (with name %s)", lastBlock.Algorithm, lastBlock.Name))
				}
				state = 0
				continue L
			}
			// len of line is not 0, thus we must parse a constraint, depending on
			// the last algorithm

			// this should no thappen
			if lastBlock == nil {
				return nil, fmt.Errorf("Internal error: Invalid configuration while parsing")
			}

			var cons Constraint
			var info *ConstraintInfo
			var err error
			switch lastBlock.Algorithm {
			case BcryptName:
				var bcons BcryptConstraint
				bcons, info, err = ParseBcryptCons(line)
				if err != nil {
					return nil, err
				}
				cons = MakeBcryptConstraint(bcons)
			case ScryptName:
				var scons ScryptConstraint
				scons, info, err = ParseScryptCons(line)
				if err != nil {
					return nil, err
				}
				cons = MakeScryptConstraint(scons)
			case Argon2iName:
				var argon2cons Argon2Constraint
				argon2cons, info, err = ParseArgon2Cons(line)
				if err != nil {
					return nil, err
				}
				cons = MakeArgon2iConstraint(argon2cons)
			case Argon2idName:
				var argon2cons Argon2Constraint
				argon2cons, info, err = ParseArgon2Cons(line)
				if err != nil {
					return nil, err
				}
				cons = MakeArgon2idConstraint(argon2cons)
			default:
				return nil, fmt.Errorf("Internal error: Parsed an invalid algorithm name: %s", lastBlock.Algorithm)
			}
			lastBlock.Constraints = append(lastBlock.Constraints, cons)
			lastBlock.Infos = append(lastBlock.Infos, info)
		default:
			return nil, fmt.Errorf("Internal error: Invalid parser state %d", state)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if lastBlock != nil && len(lastBlock.Constraints) == 0 {
		return nil, NewConstraintSyntaxError(fmt.Sprintf("No constraints in block for %s (with name %s)", lastBlock.Algorithm, lastBlock.Name))
	}
	return result, nil
}

// ParseConstraintsFromFile works like ParseConstraints and reads the content
// from a file.
func ParseConstraintsFromFile(filename string) ([]*ConstraintBlock, error) {
	f, openErr := os.Open(filename)
	if openErr != nil {
		defer f.Close()
	}
	return ParseConstraints(f)
}
