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
	"fmt"
	"strings"
)

type PHC struct {
	ID         string
	Params     []string
	Salt, Hash string
}

// I think a pool might be good here, but should be fine...

func (phc *PHC) Encode(info *PHCInfo) (string, error) {
	// TODO add error handling: only option parameters empty & length checking
	if len(phc.Params) != len(info.ParamInfos) {
		return "", fmt.Errorf("gopherbounce/phc: Parameter values and number of parameter description doesn't match")
	}
	var result strings.Builder
	fmt.Fprint(&result, "$", phc.ID)
	nonEmpty := -1
	for i, p := range phc.Params {
		if p != "" {
			nonEmpty = i
		}
		break
	}
	if nonEmpty >= 0 {
		fmt.Fprintf(&result, "$%s=%s", info.ParamInfos[nonEmpty].Name, phc.Params[nonEmpty])
		for i := nonEmpty + 1; i < len(info.ParamInfos); i++ {
			if phc.Params[i] != "" {
				fmt.Fprintf(&result, ",%s=%s", info.ParamInfos[i].Name, phc.Params[i])
			}
		}
	}
	if phc.Salt != "" {
		fmt.Fprint(&result, "$", phc.Salt)
		if phc.Hash != "" {
			fmt.Fprint(&result, "$", phc.Hash)
		}
	}
	return result.String(), nil
}

type PHCError string

func NewPHCError(s string) PHCError {
	return PHCError(s)
}

func (err PHCError) Error() string {
	return string(err)
}

func isValidPHCIdentifier(r rune) bool {
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') || r == '-'
}

func isValidPHCParam(r rune) bool {
	// simplification, they happen to be the same
	return isValidPHCIdentifier(r)
}

func isValidPHCVal(r rune) bool {
	return isValidPHCIdentifier(r) || r == '/' || r == '+' || r == '.'
}

func isValidPHCSalt(r rune) bool {
	// again made simple
	return isValidPHCVal(r)
}

func isValidPHCB64(r rune) bool {
	return isValidPHCIdentifier(r) || r == '+' || r == '/'
}

func parsePHCIdentifier(s string, minLength, maxLength int,
	validate func(rune) bool,
	delim func(rune) bool) (string, string, error) {
	for index, r := range s {
		if delim(r) {
			id := s[:index]
			// len(id) is fine here because we have only ascii chars
			n := len(id)
			if (minLength > 0 && n < minLength) || (maxLength >= 0 && n > maxLength) {
				return "", "", NewPHCError(fmt.Sprintf("PHC ID is not valid: Must be of length >= %d and <= %d",
					minLength, maxLength))
			}
			return id, s[index:], nil
		}
		if !validate(r) {
			return "", "", NewPHCError(fmt.Sprintf("Invalid character in ID: %s", string(r)))
		}
	}
	n := len(s)
	if (minLength > 0 && n < minLength) || (maxLength >= 0 && n > maxLength) {
		return "", "", NewPHCError("PHC ID is not valid: Must be of length > 0 and <= 32")
	}
	return s, "", nil
}

func parsePHCID(s string) (string, string, error) {
	delim := func(r rune) bool {
		return r == '$'
	}
	return parsePHCIdentifier(s, 1, 32, isValidPHCIdentifier, delim)
}

func parsePHCValue(s string, maxLength int) (string, string, error) {
	delim := func(r rune) bool {
		return r == ',' || r == '$'
	}
	return parsePHCIdentifier(s, 1, maxLength, isValidPHCVal, delim)
}

type PHCParamInfo struct {
	Name      string
	MaxLength int
	Optional  bool
}

func NewPHCParamInfo(name string) *PHCParamInfo {
	return &PHCParamInfo{
		Name:      name,
		MaxLength: -1,
		Optional:  false,
	}
}

func parsePHCParValuePair(s string, info *PHCParamInfo) (string, string, error) {
	if strings.HasPrefix(s, info.Name) {
		// parse value
		s = s[len(info.Name):]
		// now s must start with =
		if !strings.HasPrefix(s, "=") {
			return "", "", NewPHCError(fmt.Sprintf("No value for parameter %s exists", info.Name))
		}
		s = s[len("="):]
		// now parse the value
		value, rest, err := parsePHCValue(s, info.MaxLength)
		if err != nil {
			return "", "", err
		}
		// now we're done
		return value, rest, nil
	}
	// if the parameter is optional: accept it, otherwise return error
	if info.Optional {
		return "", s, nil
	}
	return "", "", NewPHCError(fmt.Sprintf("Non-optional parameter %s not specified", info.Name))
}

func parsePHCParams(s string, infos []*PHCParamInfo) ([]string, bool, string, error) {
	result := make([]string, len(infos))
	any := false
	for i, info := range infos {
		if i != 0 {
			// in this case we must find a , at the beginning of the string
			// or the string is empty
			// if it is a comma move forward
			if strings.HasPrefix(s, ",") {
				s = s[len(","):]
			}
			// TODO should we check for errors here?
			// I mean what happens if there is no comma?
		}
		val, rest, err := parsePHCParValuePair(s, info)
		if err != nil {
			return nil, false, "", err
		}
		result[i] = val
		any = any || (val != "")
		s = rest
	}
	return result, any, s, nil
}

func parsePHCSalt(s string, minLength, maxLength int) (string, string, error) {
	delim := func(r rune) bool {
		return r == '$'
	}
	return parsePHCIdentifier(s, minLength, maxLength, isValidPHCSalt, delim)
}

func parsePHCB64(s string, minLength, maxLength int) (string, string, error) {
	delim := func(r rune) bool {
		return false
	}
	return parsePHCIdentifier(s, minLength, maxLength, isValidPHCB64, delim)
}

type PHCInfo struct {
	ParamInfos                   []*PHCParamInfo
	MinSaltLength, MaxSaltLength int
	MinHashLength, MaxHashLength int
}

func NewPHCInfo() *PHCInfo {
	return &PHCInfo{
		ParamInfos:    nil,
		MinSaltLength: -1,
		MaxSaltLength: -1,
		MinHashLength: -1,
		MaxHashLength: -1,
	}
}

func ParsePHC(s string, info *PHCInfo) (*PHC, error) {
	if !strings.HasPrefix(s, "$") {
		return nil, NewPHCError("gopherbounce.PHCParse: Empty hash string")
	}
	s = s[len("$"):]

	result := &PHC{}
	id, s, err := parsePHCID(s)
	if err != nil {
		return nil, err
	}
	result.ID = id
	if !strings.HasPrefix(s, "$") {
		// we're done, nothing follows
		// in this case the end of the string has been reached
		// just a quick assert
		if len(s) > 0 {
			return nil, NewPHCError("gopherbounce.PHCParse: Assertion failed, parsed id but string is not empty and no \"$\" found")
		}
		return result, nil
	}
	// move forward
	s = s[len("$"):]

	// now try to parse the parameters
	// because the parameters can be optional it's possible that nothing is parsed
	params, anyParam, s, err := parsePHCParams(s, info.ParamInfos)
	if err != nil {
		return nil, err
	}
	result.Params = params

	// this is a special case, after a value a single comma can happen, we have
	// to prevent this for the last value
	if strings.HasPrefix(s, ",") {
		return nil, NewPHCError("gopherbounce.PHCParse: Invalid parameter / value pair")
	}

	// now a salt can follow, if not that's okay and we're done
	if !strings.HasPrefix(s, "$") {
		// again an Assertion
		if len(s) > 0 {
			return nil, NewPHCError("gopherbounce.PHCParse: Assertion failed, parsed params but string is not empty and no \"$\" found")
		}
		return result, nil
	}

	// this must only be allowed if we parsed any parameter
	// this should not happen, but be sure
	if !anyParam {
		return nil, NewPHCError("Found additional \"$\" after not parsing any parameters, this should not happen, please report")
	}
	s = s[len("$"):]

	// now we must parse a salt
	salt, s, err := parsePHCSalt(s, info.MinSaltLength, info.MaxSaltLength)
	if err != nil {
		return nil, err
	}
	result.Salt = salt

	// now a hash may follow
	if !strings.HasPrefix(s, "$") {
		// again an Assertion
		if len(s) > 0 {
			return nil, NewPHCError("gopherbounce.PHCParse: Assertion failed, parsed params but string is not empty and no \"$\" found")
		}
		return result, nil
	}

	s = s[len("$"):]

	// now we must parse a hash
	hash, s, err := parsePHCB64(s, info.MinHashLength, info.MaxHashLength)
	if err != nil {
		return nil, err
	}
	result.Hash = hash

	// this should not happen, we must have reached the end of the string
	if s != "" {
		return nil, NewPHCError("gopherbounce.PHCParse: Assertion failed, parsed complete string but rest is not empty")
	}

	return result, nil
}

var (
	PHCScryptConfig = &PHCInfo{
		MinSaltLength: -1,
		MaxSaltLength: -1,
		MinHashLength: -1,
		MaxHashLength: -1,
		ParamInfos: []*PHCParamInfo{
			&PHCParamInfo{"ln", 2, false},
			&PHCParamInfo{"r", -1, false},
			&PHCParamInfo{"p", -1, false},
		},
	}

	PHCArgon2Config = &PHCInfo{
		MinSaltLength: -1,
		MaxSaltLength: -1,
		MinHashLength: -1,
		MaxHashLength: -1,
		ParamInfos: []*PHCParamInfo{
			&PHCParamInfo{"m", 10, false},
			&PHCParamInfo{"t", 10, false},
			&PHCParamInfo{"p", 3, false},
			&PHCParamInfo{"v", -1, true},
		},
	}
)
