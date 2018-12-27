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

// SyntaxError is used if a hashed version is not stored in a valid syntax.
type SyntaxError string

// NewSyntaxError returns a new SyntaxError.
func NewSyntaxError(cause string) SyntaxError {
	return SyntaxError(cause)
}

// Error returns the string representation of the error.
func (err SyntaxError) Error() string {
	return "Syntax error: " + string(err)
}

// String returns the string representation of the error.
func (err SyntaxError) String() string {
	return err.Error()
}

// VersionError is an error returned if the version of a hashes version is
// not compatible with the library.
type VersionError struct {
	Prefix        string
	Expected, Got string
}

// NewVersionError returns a new VersionError.
// Prefix is appended to the error message, expected and got describe the
// the version execpted resp. found.
func NewVersionError(prefix, expected, got string) VersionError {
	return VersionError{
		Prefix:   prefix,
		Expected: expected,
		Got:      got,
	}
}

// Error returns the string representation of the error.
func (err VersionError) Error() string {
	return fmt.Sprintf("%s: Invalid version, expected version %s, got %s", err.Prefix, err.Expected, err.Got)
}

// String returns the string representation of the error.
func (err VersionError) String() string {
	return err.Error()
}

// AlgIDError is returned if the hashes version has the wrong prefix for a
// certain Validator. This does not mean that the hashes version is invalid
// in general, only for the specific Validator.
type AlgIDError struct {
	Prefix        string
	Expected, Got string
}

// NewAlgIDError returns a new AlgIDError. Prefix is appended to the error
// message. Expected and got are the resp. ids.
func NewAlgIDError(prefix, expected, got string) AlgIDError {
	return AlgIDError{
		Prefix:   prefix,
		Expected: expected,
		Got:      got,
	}
}


// Error returns the string representation of the error.
func (err AlgIDError) Error() string {
	return fmt.Sprintf("%s: Invalid algorithm identifier, expected %s, got %s", err.Prefix, err.Expected, err.Got)
}

// String returns the string representation of the error.
func (err AlgIDError) String() string {
	return err.Error()
}

// PasswordMismatchError is returned if a hashes version and a clear text
// version do not match. No password details are made public by this error.
type PasswordMismatchError struct{}

// NewPasswordMismatchError returns a new PasswordMismatchError.
func NewPasswordMismatchError() PasswordMismatchError {
	return PasswordMismatchError{}
}

// Error returns the string representation of the error.
func (err PasswordMismatchError) Error() string {
	return "gopherbounce: hashed password is not the hash of the given password"
}

// String returns the string representation of the error.
func (err PasswordMismatchError) String() string {
	return err.Error()
}

// UnknownAlgError if a hashed version describes an unkown algorithm.
type UnknownAlgError struct{}

// NewUnknownAlgError returns a new UnknownAlgError.
func NewUnknownAlgError() UnknownAlgError {
	return UnknownAlgError{}
}

// Error returns the string representation of the error.
func (err UnknownAlgError) Error() string {
	return "Unknown algorithm, can't compare password"
}

// String returns the string representation of the error.
func (err UnknownAlgError) String() string {
	return err.Error()
}
