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

import "fmt"

type SyntaxError string

func NewSyntaxError(cause string) SyntaxError {
	return SyntaxError(cause)
}

func (err SyntaxError) Error() string {
	return "Syntax error: " + string(err)
}

type VersionError struct {
	Prefix        string
	Expected, Got string
}

func NewVersionError(prefix, expected, got string) VersionError {
	return VersionError{
		Prefix:   prefix,
		Expected: expected,
		Got:      got,
	}
}

func (err VersionError) Error() string {
	return fmt.Sprintf("%s: Invalid version, expected version %s, got %s", err.Prefix, err.Expected, err.Got)
}

type AlgIDError struct {
	Prefix        string
	Expected, Got string
}

func NewAlgIDError(prefix, expected, got string) AlgIDError {
	return AlgIDError{
		Prefix:   prefix,
		Expected: expected,
		Got:      got,
	}
}

func (err AlgIDError) Error() string {
	return fmt.Sprintf("%s: Invalid algorithm identifier, expected %s, got %s", err.Prefix, err.Expected, err.Got)
}

type PasswordMismatchError struct{}

func NewPasswordMismatchError() PasswordMismatchError {
	return PasswordMismatchError{}
}

func (err PasswordMismatchError) Error() string {
	return "gopherbounce: hashed password is not the hash of the given password"
}
