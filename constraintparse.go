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
	"regexp"
	"strconv"
	"strings"
)

type ConstraintSyntaxError string

func NewConstraintSyntaxError(cause string) ConstraintSyntaxError {
	return ConstraintSyntaxError(cause)
}

func (err ConstraintSyntaxError) Error() string {
	return "Syntax error: " + string(err)
}

var ConstraintLineRegex = regexp.MustCompile(`^\s*([a-zA-Z]+)\s+(<|>|<=|>=|=|≤|≥)\s+(-?\d+)\s*$`)

func ParseConstraintLine(line string) (lhs, rhs string, rel BinRelation, err error) {
	match := ConstraintLineRegex.FindStringSubmatch(line)
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

func ParseBcryptCostCons(line string) (BcryptConstraint, error) {
	lhs, bound64, rel, err := ParseConstraintInt(line, strconv.IntSize)
	if err != nil {
		return nil, err
	}
	bound := int(bound64)
	switch strings.ToLower(lhs) {
	case "cost", "c":
		return BcryptCostConstraint(bound, rel), nil
	default:
		return nil, NewConstraintSyntaxError(fmt.Sprintf("Invalid left-hand side of relation, must be \"cost\", got %s", lhs))
	}
}
