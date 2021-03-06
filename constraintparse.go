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
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ConstraintSyntaxError is an error returned if an error occurred due to
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
	// IgnoreAlgLineRx is the regex used to parse a algorithm ignore line.
	IgnoreAlgLineRx = regexp.MustCompile(`^\s*ignore\s+([a-zA-Z]+)\s*$`)
)

// ParseConstraintLine parses a single line constraint line (with
// ConstraintLineRx).
// It returns the lhs and rhs as a string.
// Example of a line "cost < 10" that would return "cost" "10" Less.
// This function does not check if the identifiers are valid. For example
// "foo < 10" would be valid.
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
// This function does not check if the algorithm name is valid, for example
// "[foo]" would be valid.
func ParseHeadLine(line string) (algorithm, name string, err error) {
	match := HeadLineRx.FindStringSubmatch(line)
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

// ParseAlgIgnoreLine parses a algorithm ignore line (with IgnoreAlgLineRx).
// Example of a line: "ignore bcrypt". This would return "bcrypt".
// This function does not check if the algorithm name is valid, for example
// "ignore foo" would be valid.
func ParseAlgIgnoreLine(line string) (algorithm string, err error) {
	match := IgnoreAlgLineRx.FindStringSubmatch(line)
	switch len(match) {
	case 0:
		err = NewConstraintSyntaxError("Can't match line")
	case 2:
		algorithm = match[1]
	default:
		err = fmt.Errorf("Internal error: Regex match in gopherbounce.ParseAlgIgnoreLine has length %d", len(match))
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
func ParseBcryptCons(line string) (BcryptConstraint, error) {
	lhs, bound64, rel, err := ParseConstraintInt(line, strconv.IntSize)
	if err != nil {
		return BcryptConstraint{}, err
	}
	bound := int(bound64)
	switch strings.ToLower(lhs) {
	case "cost", "c":
		return NewBcryptConstraint(bound, rel), nil
	default:
		return BcryptConstraint{}, NewConstraintSyntaxError(fmt.Sprintf("Invalid left-hand side of relation, must be \"cost\", got %s", lhs))
	}
}

// ParseScryptCons parses a constraint for scrypt. It allows the following
// format: "LHS RELATION BOUND" where LHS is either "N", "R", "P" or "KeyLen".
func ParseScryptCons(line string) (ScryptConstraint, error) {
	lhs, bound64, rel, err := ParseConstraintInt(line, strconv.IntSize)
	if err != nil {
		return ScryptConstraint{}, err
	}
	switch strings.ToLower(lhs) {
	case "n":
		return NewScryptConstraint(bound64, "n", rel), nil
	case "rounds":
		return NewScryptConstraint(bound64, "rounds", rel), nil
	case "r":
		return NewScryptConstraint(bound64, "r", rel), nil
	case "p":
		return NewScryptConstraint(bound64, "p", rel), nil
	case "keylen", "len":
		return NewScryptConstraint(bound64, "keylen", rel), nil
	default:
		return ScryptConstraint{}, NewConstraintSyntaxError(fmt.Sprintf("Invalid left-hand side of relation, must be N, rounds, R, P or KeyLen, got %s", lhs))
	}
}

// ParseArgon2Cons parses a constraint for argon2 (argon2i and argon2id). It
// allows the following format: "LHS RELATION BOUND" where LHS is either "time",
// "memory", "Threads" or "KeyLen".
func ParseArgon2Cons(line string) (Argon2Constraint, error) {
	lhs, rhsStr, rel, err := ParseConstraintLine(line)
	if err != nil {
		return Argon2Constraint{}, err
	}
	var bound64 uint64
	switch strings.ToLower(lhs) {
	case "time", "t":
		bound64, err = strconv.ParseUint(rhsStr, 10, 32)
		if err != nil {
			return Argon2Constraint{}, NewConstraintSyntaxError(err.Error())
		}
		return NewArgon2Constraint(bound64, "time", rel), nil
	case "memory", "m":
		bound64, err = strconv.ParseUint(rhsStr, 10, 32)
		if err != nil {
			return Argon2Constraint{}, NewConstraintSyntaxError(err.Error())
		}
		return NewArgon2Constraint(bound64, "memory", rel), nil
	case "keylen", "len":
		bound64, err = strconv.ParseUint(rhsStr, 10, 32)
		if err != nil {
			return Argon2Constraint{}, NewConstraintSyntaxError(err.Error())
		}
		return NewArgon2Constraint(bound64, "keylen", rel), nil
	case "threads", "p":
		bound64, err = strconv.ParseUint(rhsStr, 10, 8)
		if err != nil {
			return Argon2Constraint{}, NewConstraintSyntaxError(err.Error())
		}
		return NewArgon2Constraint(bound64, "threads", rel), nil
	default:
		return Argon2Constraint{}, NewConstraintSyntaxError(fmt.Sprintf("Invalid left-hand side of relation, must be time, memory, threads or KeyLen, got %s", lhs))
	}
}

// ConstraintsCol is a collection of "standard" constraints (for bcrypt,
// scrypt, argon2i and argon2id). Such a collection can be parsed from
// a file (or any reader with the correct syntax) with ParseConstraints.
//
// It also stores a list of all algorithms that should be completely ignored
// (AlgConstraints).
type ConstraintsCol struct {
	AlgConstraints      []HashAlg
	BcryptConstraints   []BcryptConstraint
	ScryptConstraints   []ScryptConstraint
	Argon2iConstraints  []Argon2Constraint
	Argon2idConstraints []Argon2Constraint
}

// NewConstraintCol returns an empty constraints collection.
func NewConstraintCol() *ConstraintsCol {
	return &ConstraintsCol{}
}

// WriteConstraints writes all constraints to a file. The output is a file
// that can be parsed by ParseConstraints.
// If printTime is true a timestamp will be added as a comment to the output
// specifying the time the config file was created.
func (col *ConstraintsCol) WriteConstraints(w io.Writer, printTime bool) (int, error) {
	res := 0

	var n int
	var err error

	if printTime {
		now := time.Now()
		nowFormat := now.Format(time.RFC1123)
		n, err = fmt.Fprintf(w, "# Created on %s\n\n", nowFormat)
		res += n
		if err != nil {
			return res, err
		}
	}

	// first write all algorithms that should be completely ignored
	for _, alg := range col.AlgConstraints {
		var algName string
		switch alg {
		case BcryptAlg:
			algName = "bcrypt"
		case ScryptAlg:
			algName = "scrypt"
		case Argon2iAlg:
			algName = "argon2i"
		case Argon2idAlg:
			algName = "argon2id"
		default:
			return res, fmt.Errorf("Invalid algorithm %d", alg)
		}
		n, err = fmt.Fprint(w, "ignore ", algName, "\n\n")
		res += n
		if err != nil {
			return res, err
		}
	}

	if len(col.BcryptConstraints) > 0 {
		n, err = WriteBcryptConstraints(w, col.BcryptConstraints)
		res += n
		if err != nil {
			return res, err
		}
		// don't forget an extra blank line
		n, err = fmt.Fprintln(w)
		res += n
		if err != nil {
			return res, err
		}
	}

	if len(col.ScryptConstraints) > 0 {
		n, err = WriteScryptConstraints(w, col.ScryptConstraints)
		res += n
		if err != nil {
			return res, err
		}
		// don't forget an extra blank line
		n, err = fmt.Fprintln(w)
		res += n
		if err != nil {
			return res, err
		}
	}

	if len(col.Argon2iConstraints) > 0 {
		n, err = WriteArgon2iConstraints(w, col.Argon2iConstraints)
		res += n
		if err != nil {
			return res, err
		}
		// don't forget an extra blank line
		n, err = fmt.Fprintln(w)
		res += n
		if err != nil {
			return res, err
		}
	}

	if len(col.Argon2idConstraints) > 0 {
		n, err = WriteArgon2idConstraints(w, col.Argon2idConstraints)
		res += n
		if err != nil {
			return res, err
		}
		// don't forget an extra blank line
		n, err = fmt.Fprintln(w)
		res += n
		if err != nil {
			return res, err
		}
	}

	return res, nil
}

// ParseConstraints parses all constraints from a reader, see the README for
// more details.
func ParseConstraints(r io.Reader) (*ConstraintsCol, error) {
	result := NewConstraintCol()
	scanner := bufio.NewScanner(r)
	state := 0
	var lastAlg HashAlg = -1
L:
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch state {
		case 0:
			if len(line) == 0 || strings.HasPrefix(line, "#") {
				continue L
			}

			// first we try ignore algorithm regex
			ignoreAlgName, ignoreAlgErr := ParseAlgIgnoreLine(line)
			if ignoreAlgErr == nil {
				// success, add
				// get algorithm type
				var ignoreAlg HashAlg
				ignoreAlg, ignoreAlgErr = ParseAlg(ignoreAlgName)
				// if there is an error now there is a real error
				if ignoreAlgErr != nil {
					return nil, NewConstraintSyntaxError("Invalid algorithm name")
				}
				result.AlgConstraints = append(result.AlgConstraints, ignoreAlg)
				// we continue the loop, state remains unchanged
				// if err != nil we simply continue after this if
				continue L
			}

			// must be a valid heading
			// we ignore the name
			algorithm, _, err := ParseHeadLine(line)
			if err != nil {
				return nil, err
			}
			alg, err := ParseAlg(algorithm)
			if err != nil {
				return nil, NewConstraintSyntaxError("Invalid algorithm name")
			}
			lastAlg = alg
			state = 1
		case 1:
			// now we must either parse an empty line (meaning end of block)
			// or a constraint
			if strings.HasPrefix(line, "#") {
				continue L
			}
			if len(line) == 0 {
				// now we must finish the current block
				state = 0
				lastAlg = -1
				continue L
			}
			// len of line is not 0, thus we must parse a constraint, depending on
			// the last algorithm

			switch lastAlg {
			case BcryptAlg:
				cons, err := ParseBcryptCons(line)
				if err != nil {
					return nil, err
				}
				result.BcryptConstraints = append(result.BcryptConstraints, cons)
			case ScryptAlg:
				cons, err := ParseScryptCons(line)
				if err != nil {
					return nil, err
				}
				result.ScryptConstraints = append(result.ScryptConstraints, cons)
			case Argon2iAlg:
				cons, err := ParseArgon2Cons(line)
				if err != nil {
					return nil, err
				}
				result.Argon2iConstraints = append(result.Argon2iConstraints, cons)
			case Argon2idAlg:
				cons, err := ParseArgon2Cons(line)
				if err != nil {
					return nil, err
				}
				result.Argon2idConstraints = append(result.Argon2idConstraints, cons)
			default:
				return nil, fmt.Errorf("Internal error: Parsed an invalid algorithm: %v", lastAlg)
			}
		default:
			return nil, fmt.Errorf("Internal error: Invalid parser state %d", state)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// ParseConstraintsFromFile works like ParseConstraints and reads the content
// from a file.
func ParseConstraintsFromFile(filename string) (*ConstraintsCol, error) {
	f, openErr := os.Open(filename)
	if openErr != nil {
		return nil, openErr
	}
	defer f.Close()
	return ParseConstraints(f)
}

// WriteBcryptConstraints writes all constraints to a file s.t. they can
// be parsed again later.
func WriteBcryptConstraints(w io.Writer, cs []BcryptConstraint) (int, error) {
	res := 0

	n, err := fmt.Fprintln(w, "[bcrypt]")
	res += n
	if err != nil {
		return res, err
	}

	for _, c := range cs {
		n, err = fmt.Fprintf(w, "%s %s %d\n", "Cost", c.Rel, c.CostBound)
		res += n
		if err != nil {
			return res, err
		}
	}

	return res, nil
}

// WriteScryptConstraints writes all constraints to a file s.t. they can
// be parsed again later.
func WriteScryptConstraints(w io.Writer, cs []ScryptConstraint) (int, error) {
	res := 0

	n, err := fmt.Fprintln(w, "[scrypt]")
	res += n
	if err != nil {
		return res, err
	}

	for _, c := range cs {
		n, err = fmt.Fprintf(w, "%s %s %d\n", c.VarName, c.Rel, c.Bound)
		res += n
		if err != nil {
			return res, err
		}
	}

	return res, nil
}

func writeArgon2Constraints(w io.Writer, alg string, cs []Argon2Constraint) (int, error) {
	res := 0

	n, err := fmt.Fprintf(w, "[%s]\n", alg)
	res += n
	if err != nil {
		return res, err
	}

	for _, c := range cs {
		n, err = fmt.Fprintf(w, "%s %s %d\n", c.VarName, c.Rel, c.Bound)
		res += n
		if err != nil {
			return res, err
		}
	}

	return res, nil
}

// WriteArgon2iConstraints writes all constraints to a file s.t. they can
// be parsed again later.
func WriteArgon2iConstraints(w io.Writer, cs []Argon2Constraint) (int, error) {
	return writeArgon2Constraints(w, "argon2i", cs)
}

// WriteArgon2idConstraints writes all constraints to a file s.t. they can
// be parsed again later.
func WriteArgon2idConstraints(w io.Writer, cs []Argon2Constraint) (int, error) {
	return writeArgon2Constraints(w, "argon2id", cs)
}
