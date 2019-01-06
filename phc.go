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
	"errors"
	"fmt"
	"io"
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

func PHCValidateID(id string) error {
	// check if identifier is valid
	if !phcAllValid(isValidPHCIdentifier, id) {
		return fmt.Errorf("gopherbounce/phc: Invalid character in phc identifier \"%s\"", id)
	}
	if len(id) > 32 {
		return errors.New("gopherbounce/phc: Algorithm identifier is too long")
	}
	return nil
}

// EncodePHCID writes the algorithm id in the phc format to the writer.
// The string written is simply "$ID".
// It returns the number of bytes written.
func EncodePHCID(w io.Writer, id string) (int, error) {
	// validate id
	err := PHCValidateID(id)
	if err != nil {
		return 0, err
	}
	return fmt.Fprint(w, "$", id)
}

func PHCValidateParamName(param string) error {
	if !phcAllValid(isValidPHCParam, param) {
		return fmt.Errorf("gopherbounce/phc: Invalid parameter name: \"%s\"", param)
	}
	if len(param) > 32 {
		return fmt.Errorf("gopherbounce/phc: Parameter name \"%s\" is too long", param)
	}
	return nil
}

func PHCValidateValue(value string, maxLength int) error {
	if !phcAllValid(isValidPHCVal, value) {
		return fmt.Errorf("gopherbounce/phc: Invalid parameter value: \"%s\"", value)
	}
	if maxLength >= 0 && len(value) > maxLength {
		return fmt.Errorf("gopherbounce/phc: Parameter value \"%s\" exceeds max length of %d", value, maxLength)
	}
	return nil
}

// EncodePHCParams writes the pch parameters to the writer.
// values and infos must be of the same length. See PCH type documentation
// for more details.
// If no parameters are written (parameter is empty, all parameters are optional
// and not given) nothing is written to the writer.
// It returns the number of bytes written. An error might occur if the
// parameter values do not match the description (length, non-optional and not
// given etc.) and if writing to w fails.
func EncodePHCParams(w io.Writer, values []string, infos []*PHCParamInfo) (int, error) {
	result := 0
	if len(values) != len(infos) {
		return result, fmt.Errorf("gopherbounce/phc: Parameter values and number of parameter description don't match")
	}
	nonEmpty := -1
	for i, p := range values {
		if p == "" {
			if !infos[i].Optional {
				return result, fmt.Errorf("gopherbounce/phc: No value for non-optional parameter %s", infos[i].Name)
			}
		} else {
			nonEmpty = i
			break
		}
	}
	if nonEmpty < 0 {
		return result, nil
	}
	// boundary checking

	// a bit of code duplication here, but not too much :)
	maxLength := infos[nonEmpty].MaxLength
	if validateErr := PHCValidateParamName(infos[nonEmpty].Name); validateErr != nil {
		return result, validateErr
	}
	if validateErr := PHCValidateValue(values[nonEmpty], maxLength); validateErr != nil {
		return result, validateErr
	}
	// print first
	firstN, firstErr := fmt.Fprint(w, "$", infos[nonEmpty].Name, "=", values[nonEmpty])
	result += firstN
	if firstErr != nil {
		return result, firstErr
	}
	for i := nonEmpty + 1; i < len(infos); i++ {
		nextValue := values[i]
		nextInfo := infos[i]
		if nextValue == "" {
			if !nextInfo.Optional {
				return result, fmt.Errorf("gopherbounce/phc: No value for non-optional parameter %s", nextInfo.Name)
			}
		} else {
			maxLength = nextInfo.MaxLength
			if validateErr := PHCValidateParamName(nextInfo.Name); validateErr != nil {
				return result, validateErr
			}
			if validateErr := PHCValidateValue(nextValue, maxLength); validateErr != nil {
				return result, validateErr
			}
			n, err := fmt.Fprint(w, ",", nextInfo.Name, "=", nextValue)
			result += n
			if err != nil {
				return result, err
			}
		}
	}
	return result, nil
}

func PHCValidateSalt(salt string, minLength, maxLength int) error {
	saltLen := len(salt)
	if (minLength > 0 && saltLen < minLength) || (maxLength >= 0 && saltLen > maxLength) {
		return fmt.Errorf("gopherbounce/phc: Salt length not in the required range, length must be in [%d, %d]", minLength, maxLength)
	}
	if !phcAllValid(isValidPHCSalt, salt) {
		return errors.New("gopherbounce/phc: Invalid character in salt")
	}
	return nil
}

// EncodePHCSalt writes the salt to the writer.
// If the salt is empty nothing is written.
// It returns the number of bytes written. An error might occur if the salt
// is invalid (according to min/max length) or if writing to w fails.
// The length can be < 0 in which case they're ignored.
func EncodePHCSalt(w io.Writer, salt string, minLength, maxLength int) (int, error) {
	if validateErr := PHCValidateSalt(salt, minLength, maxLength); validateErr != nil {
		return 0, validateErr
	}
	if salt == "" {
		return 0, nil
	}
	return fmt.Fprint(w, "$", salt)
}

func PHCValidateHash(hash string, minLength, maxLength int) error {
	hashLen := len(hash)
	if (minLength > 0 && hashLen < minLength) || (maxLength >= 0 && hashLen > maxLength) {
		return fmt.Errorf("gopherbounce/phc: Hash length not in the required range, length must be in [%d, %d]", minLength, maxLength)
	}
	if !phcAllValid(isValidPHCB64, hash) {
		return errors.New("gopherbounce/phc: Invalid character in hash")
	}
	return nil
}

// EncodePHCHash writes the hash to the writer.
// If the hash is empty nothing is written.
// It returns the number of bytes written. An error might occur if the hash
// is invalid (according to min/max length) or if writing to w fails.
// The length can be < 0 in which case they're ignored.
func EncodePHCHash(w io.Writer, hash string, minLength, maxLength int) (int, error) {
	if validateErr := PHCValidateHash(hash, minLength, maxLength); validateErr != nil {
		return 0, validateErr
	}

	if hash == "" {
		return 0, nil
	}
	return fmt.Fprint(w, "$", hash)
}

// I think a pool might be good here, but should be fine...

// Encode encodes the pch object to a string. The info contains the
// specification used for the encoding. Optional parameters (set to the empty
// string in phc.Params) are not contained in the result.
//
// If you want to create your own phc-like format you may want to look at the
// EncodePHC... functions, like EncodePHCParams. It basically combines those
// methods.
//
// It returns the number of bytes written. An error might occur if the
// parameters do not satisfy the description or if writing to w fails.
func (phc *PHC) Encode(w io.Writer, info *PHCInfo) (int, error) {
	result := 0
	// avoid writing something if even this fails, this will be checked again
	// later but that's fine
	if len(phc.Params) != len(info.ParamInfos) {
		return result, fmt.Errorf("gopherbounce/phc: Parameter values and number of parameter description don't match")
	}

	// id
	n, err := EncodePHCID(w, phc.ID)
	result += n
	if err != nil {
		return result, err
	}

	// params
	n, err = EncodePHCParams(w, phc.Params, info.ParamInfos)
	result += n
	if err != nil {
		return result, err
	}

	// salt
	n, err = EncodePHCSalt(w, phc.Salt, info.MinSaltLength, info.MaxSaltLength)
	result += n
	if err != nil {
		return result, err
	}

	// only if salt has been written write a hash
	if n == 0 {
		// if a hash exists this is an error, hash can only exist if
		// salt exists
		if phc.Hash != "" {
			return result, errors.New("Hash exists without a salt, error")
		}
	} else {
		// salt exists, write hash (if exists)
		n, err = EncodePHCHash(w, phc.Hash, info.MinHashLength, info.MaxHashLength)
		result += n
		if err != nil {
			return result, err
		}
	}

	return result, nil
}

// EncodeString encodes the pch object to a string. For more details see Encode.
func (phc *PHC) EncodeString(info *PHCInfo) (string, error) {
	var builder strings.Builder

	_, err := phc.Encode(&builder, info)
	if err != nil {
		return "", err
	}
	return builder.String(), nil
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

func phcAllValid(f func(r rune) bool, s string) bool {
	for _, r := range s {
		if !f(r) {
			return false
		}
	}
	return true
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
