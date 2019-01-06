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

// PHC is a format for hash encodings, see
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
// scrypt and argon2 use this encoding, though not everything is supported
// at the moment.
//
// A PHC value is used to describe the parsed data. The ID is the algorithm id,
// for example "scrypt". Salt and Hash are the salt and hash strings, usually
// that is the base64 encoding of a binary salt/hash and must be decoded first.
//
// Params are the value of the phc parameters. The names of these parameters
// are given by the algorithm specification, that is before parsing.
// See PHCInfo type for more information. For optional parameters that are not
// present in the phc string the parameter value is set to the empty string "".
// This should be fine since each other valid value should have at least
// length one.
type PHC struct {
	ID         string
	Params     []string
	Salt, Hash string
}

// I think a pool might be good here, but should be fine...

// Encode encodes the pch object to a string. The info contains the
// specification used for the encoding. Optional parameters (set to the empty
// string in phc.Params) are not contained in the result.
func (phc *PHC) Encode(info *PHCInfo) (string, error) {
	// TODO add error handling: only option parameters empty & length checking
	if len(phc.Params) != len(info.ParamInfos) {
		return "", fmt.Errorf("gopherbounce/phc: Parameter values and number of parameter description doesn't match")
	}
	var result strings.Builder
	fmt.Fprint(&result, "$", phc.ID)
	nonEmpty := -1
	for i, p := range phc.Params {
		if p == "" {
			if !info.ParamInfos[i].Optional {
				return "", fmt.Errorf("gopherbounce/phc: No value for non-optional parameter %s", info.ParamInfos[i].Name)
			}
		} else {
			nonEmpty = i
			break
		}
	}
	if nonEmpty >= 0 {
		// boundary checking
		maxLength := info.ParamInfos[nonEmpty].MaxLength
		if maxLength >= 0 && len(phc.Params[nonEmpty]) > maxLength {
			return "", fmt.Errorf("gopherbounce/phc: Value for parameter %s exceeds max length of %d", info.ParamInfos[nonEmpty].Name, maxLength)
		}
		fmt.Fprintf(&result, "$%s=%s", info.ParamInfos[nonEmpty].Name, phc.Params[nonEmpty])
		for i := nonEmpty + 1; i < len(info.ParamInfos); i++ {
			nextParam := phc.Params[i]
			nextInfo := info.ParamInfos[i]
			if nextParam == "" {
				if !nextInfo.Optional {
					return "", fmt.Errorf("gopherbounce/phc: No value for non-optional parameter %s", nextInfo.Name)
				}
			} else {
				maxLength = nextInfo.MaxLength
				if maxLength >= 0 && len(nextParam) > maxLength {
					return "", fmt.Errorf("gopherbounce/phc: Value for parameter %s exceeds max length of %d", nextInfo.Name, maxLength)
				}
				fmt.Fprintf(&result, ",%s=%s", nextInfo.Name, nextParam)
			}
		}
	}
	saltLen := len(phc.Salt)
	minSalt, maxSalt := info.MinSaltLength, info.MaxSaltLength
	if (minSalt > 0 && saltLen < minSalt) || (maxSalt >= 0 && saltLen > maxSalt) {
		return "", fmt.Errorf("gopherbounce/phc: Salt lengt not in the required range, length must be in [%d, %d]", minSalt, maxSalt)
	}
	hashLen := len(phc.Hash)
	minHash, maxHash := info.MinHashLength, info.MaxHashLength
	if (minHash > 0 && hashLen < minHash) || (maxHash >= 0 && hashLen > maxHash) {
		return "", fmt.Errorf("gopherbounce/phc: Hash lengt not in the required range, length must be in [%d, %d]", minHash, maxHash)
	}
	if phc.Salt != "" {
		fmt.Fprint(&result, "$", phc.Salt)
		if phc.Hash != "" {
			fmt.Fprint(&result, "$", phc.Hash)
		}
	}
	return result.String(), nil
}

// PHCError is returned by the pch parse function.
type PHCError string

// NewPHCError returns a new PHCError.
func NewPHCError(s string) PHCError {
	return PHCError(s)
}

func (err PHCError) Error() string {
	return string(err)
}

// the following functions implement char classes as defined for phc.

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

// parsePHCIdentifier parses a part from the string s. It parses the following
// part:
// it finds the prefix of s in which all characters are in the character class
// defined by the validate function. It stops on the first character for which
// delim returns true or the end of the string.
//
// It validates the parsed prefix by checking it against minLength and
// maxLength,bot of which can be < 0 in which case no boundary checking is done.
//
// It returns the prefix of s that was parsed and the rest of the string (what
// can be parsed by other methods).
//
// Note that the prefix can be empty.
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

// PHCParamInfo describes information about a parameter in pch.
// A parameter has a name (like "r" in scrypt). MaxLength is the maximal length
// the parameter is allowed to have. We allow -1 which means that there is no
// boundary.
// Optional should be set to true if the parameter is optional.
type PHCParamInfo struct {
	Name      string
	MaxLength int
	Optional  bool
}

// NewPHCParamInfo returns a new phc parameter without a max length and
// optional set to false.
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

// PHCInfo bundles information about a PHC hash string.
// It describes information about the parameters (in the ParamInfos slice,
// the order in the slice implies the order of the parameters) as well
// as minimum and maximum lengths for both the salt and the hash.
// All boundaries can be set to -1, meaning that no min/max value is set.
type PHCInfo struct {
	ParamInfos                   []*PHCParamInfo
	MinSaltLength, MaxSaltLength int
	MinHashLength, MaxHashLength int
}

// NewPHCInfo returns a new PHCInfo with empty parameters and no restrictions
// on the salt / hash length.
func NewPHCInfo() *PHCInfo {
	return &PHCInfo{
		ParamInfos:    nil,
		MinSaltLength: -1,
		MaxSaltLength: -1,
		MinHashLength: -1,
		MaxHashLength: -1,
	}
}

// ParsePHC parses a phc string and returns the result as a PHC object.
// The info is used to check the format against the input string.
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
	// PHCScryptConfig is the phc description of scrypt hashes.
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

	// PHCArgon2Config is the phc description of argon2 hashes.
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
