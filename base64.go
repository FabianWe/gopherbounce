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

import "encoding/base64"

// Base64Encoding is the internal reprensetation of a base64 encoding.
type Base64Encoding struct {
	Alphabet string
	Encoding *base64.Encoding
}

// NewBase64Encoding returns a new Base64Encoding.
func NewBase64Encoding(alphabet string) *Base64Encoding {
	return &Base64Encoding{
		Alphabet: alphabet,
		Encoding: base64.NewEncoding(alphabet),
	}
}

// SetAlphabet sets the encoding alphabet to a new alphabet.
func (enc *Base64Encoding) SetAlphabet(alphabet string) {
	enc.Alphabet = alphabet
	enc.Encoding = base64.NewEncoding(alphabet)
}

// Base64Encode encodes the source to base64 using the alphabet.
func (enc *Base64Encoding) Base64Encode(src []byte) []byte {
	n := enc.Encoding.EncodedLen(len(src))
	dst := make([]byte, n)
	enc.Encoding.Encode(dst, src)
	return dst[:n]
}

// Base64Decode decodes the source using the alphabet.
func (enc *Base64Encoding) Base64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, enc.Encoding.DecodedLen(len(src)))
	n, err := enc.Encoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// Defaultalphabet is the alphabet used by most algorithms.
const Defaultalphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// DefaultEncoding is the internal encoding based on Defaultalphabet.
var DefaultEncoding = NewBase64Encoding(Defaultalphabet)

// Base64Encode encodes the source to base64 using the default encoding.
func Base64Encode(src []byte) []byte {
	return DefaultEncoding.Base64Encode(src)
}

// Base64Decode decodes the source using the encoding.
func Base64Decode(src []byte) ([]byte, error) {
	return DefaultEncoding.Base64Decode(src)
}
